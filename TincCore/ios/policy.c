/*
    policy.c -- rule-based routing for the iOS packet tunnel (see policy.h)

    Rules file format (a subset of Shadowrocket/Surge configuration):

      [General]
      dns-server = 1.1.1.1            resolver for names matched by a rule,
                                      queried through the rule's node
      direct-dns-server = 1.1.1.1     resolver for other names, queried directly
      mesh-dns-server = 10.0.0.53     resolver inside the mesh (normal routing)
      mesh-domains = corp, home.lan   names sent to mesh-dns-server

      [Proxy Group]
      streaming = fallback, node_x, node_y    first reachable member
      auto = url-test, node_x, node_y         lowest UDP round trip (tinc's own probes)
      pinned = select, node_x, node_y         the first member

      [Rule]
      DOMAIN,example.com,node_x
      DOMAIN-SUFFIX,netflix.com,streaming
      DOMAIN-KEYWORD,google,auto
      IP-CIDR,203.0.113.0/24,node_y
      IP-CIDR6,2001:db8::/32,node_y
      DOMAIN-SUFFIX,ads.example,REJECT
      FINAL,DIRECT

    A policy is a tinc node name, a group, DIRECT (not through the mesh,
    or for addresses already in the tunnel: normal Subnet routing) or
    REJECT. The first matching rule wins.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "../tinc/system.h"

#include "../tinc/event.h"
#include "../tinc/logger.h"
#include "../tinc/net.h"
#include "../tinc/node.h"
#include "../tinc/splay_tree.h"
#include "../tinc/subnet.h"
#include "../tinc/utils.h"
#include "../tinc/xalloc.h"

#include "policy.h"
#include "tinc_ios_util.h"

/* ---------------------------------------------------------------------
   Configuration
   --------------------------------------------------------------------- */

enum { T_DIRECT = 0, T_REJECT = 1 };   /* fixed target indices */
enum { K_DIRECT, K_REJECT, K_NODE, K_GROUP };
enum { G_FALLBACK, G_FASTEST, G_SELECT };
enum { R_DOMAIN, R_SUFFIX, R_KEYWORD, R_CIDR };

typedef struct target_t {
	int kind;
	char *name;
	int group;
} target_t;

typedef struct group_t {
	char *name;
	int type;
	int *members;   /* target indices */
	int nmembers;
	char *member_list; /* raw text, resolved after all groups are known */
	int line;
} group_t;

typedef struct rule_t {
	int type;
	char *pattern;  /* lowercase domain or keyword */
	int family;     /* for R_CIDR */
	uint8_t addr[16];
	int prefix;
	int target;
} rule_t;

typedef struct dnsaddr_t {
	bool set;
	int family;
	uint8_t addr[16];
	uint16_t port;
} dnsaddr_t;

struct policy_t {
	target_t *targets;
	int ntargets;
	group_t *groups;
	int ngroups;
	rule_t *rules;
	int nrules;
	int final_target;
	dnsaddr_t dns_server;
	dnsaddr_t direct_dns;
	dnsaddr_t mesh_dns;
	char **mesh_domains;
	int nmesh_domains;
	char **warnings;
	int nwarnings;
};

/* ---------------------------------------------------------------------
   Small helpers
   --------------------------------------------------------------------- */

typedef struct strbuf_t {
	char *buf;
	size_t len, size;
} strbuf_t;

static void sb_add(strbuf_t *sb, const char *s) {
	size_t n = strlen(s);

	if(sb->len + n + 1 > sb->size) {
		while(sb->len + n + 1 > sb->size) {
			sb->size = sb->size ? sb->size * 2 : 1024;
		}

		sb->buf = xrealloc(sb->buf, sb->size);
	}

	memcpy(sb->buf + sb->len, s, n + 1);
	sb->len += n;
}

static void sb_quoted(strbuf_t *sb, const char *s) {
	char *q = tinc_ios_json_quote(s);
	sb_add(sb, q);
	free(q);
}

static void sb_printf(strbuf_t *sb, const char *format, ...) {
	char tmp[512];
	va_list ap;
	va_start(ap, format);
	vsnprintf(tmp, sizeof(tmp), format, ap);
	va_end(ap);
	sb_add(sb, tmp);
}

static char *trim(char *s) {
	while(isspace((unsigned char)*s)) {
		s++;
	}

	size_t len = strlen(s);

	while(len && isspace((unsigned char)s[len - 1])) {
		s[--len] = 0;
	}

	return s;
}

static void lowercase(char *s) {
	for(; *s; s++) {
		*s = tolower((unsigned char)*s);
	}
}

static uint16_t get16(const uint8_t *p) {
	return (uint16_t)(p[0] << 8 | p[1]);
}

static void put16(uint8_t *p, uint16_t v) {
	p[0] = v >> 8;
	p[1] = v & 0xff;
}

static void put32(uint8_t *p, uint32_t v) {
	p[0] = v >> 24;
	p[1] = (v >> 16) & 0xff;
	p[2] = (v >> 8) & 0xff;
	p[3] = v & 0xff;
}

/* "1.2.3.4", "1.2.3.4:53", "[::1]:53" or "::1". */
static bool parse_dnsaddr(const char *text, dnsaddr_t *out) {
	char buf[128];
	snprintf(buf, sizeof(buf), "%s", text);
	char *host = trim(buf);
	char *port = NULL;

	if(*host == '[') {
		host++;
		char *end = strchr(host, ']');

		if(!end) {
			return false;
		}

		*end = 0;

		if(end[1] == ':') {
			port = end + 2;
		}
	} else if(strchr(host, ':') == strrchr(host, ':') && strchr(host, ':')) {
		port = strchr(host, ':');
		*port++ = 0;
	}

	memset(out, 0, sizeof(*out));
	out->port = 53;

	if(port) {
		int p = atoi(port);

		if(p <= 0 || p > 65535) {
			return false;
		}

		out->port = p;
	}

	if(inet_pton(AF_INET, host, out->addr) == 1) {
		out->family = AF_INET;
	} else if(inet_pton(AF_INET6, host, out->addr) == 1) {
		out->family = AF_INET6;
	} else {
		return false;
	}

	out->set = true;
	return true;
}

static bool parse_cidr(const char *text, int family, uint8_t *addr, int *prefix) {
	char buf[128];
	snprintf(buf, sizeof(buf), "%s", text);
	char *slash = strchr(buf, '/');
	int max = family == AF_INET ? 32 : 128;
	*prefix = max;

	if(slash) {
		*slash++ = 0;
		char *end;
		long p = strtol(slash, &end, 10);

		if(*end || p < 0 || p > max) {
			return false;
		}

		*prefix = (int)p;
	}

	memset(addr, 0, 16);
	return inet_pton(family, trim(buf), addr) == 1;
}

static bool prefix_match(const uint8_t *a, const uint8_t *b, int prefix) {
	int bytes = prefix / 8;
	int bits = prefix % 8;

	if(memcmp(a, b, bytes)) {
		return false;
	}

	if(bits) {
		uint8_t mask = (uint8_t)(0xff << (8 - bits));
		return (a[bytes] & mask) == (b[bytes] & mask);
	}

	return true;
}

/* ---------------------------------------------------------------------
   Parsing
   --------------------------------------------------------------------- */

static void add_warning(policy_t *p, int line, const char *format, ...) {
	char msg[256];
	va_list ap;
	va_start(ap, format);
	vsnprintf(msg, sizeof(msg), format, ap);
	va_end(ap);
	p->warnings = xrealloc(p->warnings, (p->nwarnings + 1) * sizeof(char *));
	xasprintf(&p->warnings[p->nwarnings++], "Line %d: %s", line, msg);
}

static int add_target(policy_t *p, int kind, const char *name, int group) {
	p->targets = xrealloc(p->targets, (p->ntargets + 1) * sizeof(target_t));
	p->targets[p->ntargets] = (target_t) {
		.kind = kind, .name = xstrdup(name), .group = group
	};
	return p->ntargets++;
}

/* Finds or creates the target for a policy name; -1 if it is not a valid name. */
static int lookup_target(policy_t *p, const char *name) {
	if(!strcasecmp(name, "DIRECT")) {
		return T_DIRECT;
	}

	if(!strcasecmp(name, "REJECT") || !strcasecmp(name, "REJECT-DROP") || !strcasecmp(name, "REJECT-TINYGIF")) {
		return T_REJECT;
	}

	for(int i = 2; i < p->ntargets; i++) {
		if(!strcmp(p->targets[i].name, name)) {
			return i;
		}
	}

	for(int g = 0; g < p->ngroups; g++) {
		if(!strcmp(p->groups[g].name, name)) {
			return add_target(p, K_GROUP, name, g);
		}
	}

	if(!check_id(name)) {
		return -1;
	}

	return add_target(p, K_NODE, name, -1);
}

static bool fail(char *error, size_t error_len, int line, const char *format, ...) {
	if(error && error_len) {
		char msg[256];
		va_list ap;
		va_start(ap, format);
		vsnprintf(msg, sizeof(msg), format, ap);
		va_end(ap);
		snprintf(error, error_len, "Line %d: %s", line, msg);
	}

	return false;
}

static bool parse_general(policy_t *p, char *key, char *value, int line, char *error, size_t error_len) {
	lowercase(key);
	dnsaddr_t *target = NULL;

	if(!strcmp(key, "dns-server")) {
		target = &p->dns_server;
	} else if(!strcmp(key, "direct-dns-server")) {
		target = &p->direct_dns;
	} else if(!strcmp(key, "mesh-dns-server")) {
		target = &p->mesh_dns;
	} else if(!strcmp(key, "mesh-domains")) {
		for(int i = 0; i < p->nmesh_domains; i++) {
			free(p->mesh_domains[i]);
		}

		p->nmesh_domains = 0;

		char *save = NULL;

		for(char *tok = strtok_r(value, ", ", &save); tok; tok = strtok_r(NULL, ", ", &save)) {
			lowercase(tok);

			while(*tok == '.') {
				tok++;
			}

			if(*tok) {
				p->mesh_domains = xrealloc(p->mesh_domains, (p->nmesh_domains + 1) * sizeof(char *));
				p->mesh_domains[p->nmesh_domains++] = xstrdup(tok);
			}
		}

		return true;
	} else {
		add_warning(p, line, "ignoring unsupported setting %s", key);
		return true;
	}

	/* Surge-style lists: use the first plain address. */
	char *first = NULL;
	char *save = NULL;

	for(char *tok = strtok_r(value, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
		tok = trim(tok);

		if(*tok && strcasecmp(tok, "system")) {
			first = tok;
			break;
		}
	}

	if(!first) {
		target->set = false;
		return true;
	}

	if(!parse_dnsaddr(first, target)) {
		return fail(error, error_len, line, "invalid DNS server address \"%s\"", first);
	}

	if(target == &p->dns_server && target->family != AF_INET) {
		return fail(error, error_len, line, "dns-server must be an IPv4 address");
	}

	return true;
}

static bool parse_group(policy_t *p, char *key, char *value, int line, char *error, size_t error_len) {
	char *comma = strchr(value, ',');

	if(!comma) {
		return fail(error, error_len, line, "a group needs a type and at least one member");
	}

	*comma = 0;
	char *type = trim(value);
	int gtype;

	if(!strcasecmp(type, "fallback")) {
		gtype = G_FALLBACK;
	} else if(!strcasecmp(type, "url-test") || !strcasecmp(type, "fastest") || !strcasecmp(type, "load-balance")) {
		gtype = G_FASTEST;
	} else if(!strcasecmp(type, "select")) {
		gtype = G_SELECT;
	} else {
		return fail(error, error_len, line, "unknown group type \"%s\" (use fallback, url-test or select)", type);
	}

	for(int g = 0; g < p->ngroups; g++) {
		if(!strcmp(p->groups[g].name, key)) {
			return fail(error, error_len, line, "group %s is defined twice", key);
		}
	}

	p->groups = xrealloc(p->groups, (p->ngroups + 1) * sizeof(group_t));
	p->groups[p->ngroups++] = (group_t) {
		.name = xstrdup(key), .type = gtype, .member_list = xstrdup(comma + 1), .line = line
	};
	return true;
}

static bool resolve_groups(policy_t *p, char *error, size_t error_len) {
	/* Every group gets a target, so status can report its selection even if no rule uses it. */
	for(int g = 0; g < p->ngroups; g++) {
		lookup_target(p, p->groups[g].name);
	}

	for(int g = 0; g < p->ngroups; g++) {
		group_t *group = &p->groups[g];

		char *save = NULL;

		for(char *tok = strtok_r(group->member_list, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
			tok = trim(tok);

			if(!*tok || strchr(tok, '=')) {
				continue;    /* url=..., interval=... */
			}

			int t = lookup_target(p, tok);

			if(t < 0) {
				return fail(error, error_len, group->line, "\"%s\" is not a node, group, DIRECT or REJECT", tok);
			}

			if(p->targets[t].kind == K_GROUP && p->targets[t].group == g) {
				return fail(error, error_len, group->line, "group %s contains itself", group->name);
			}

			group->members = xrealloc(group->members, (group->nmembers + 1) * sizeof(int));
			group->members[group->nmembers++] = t;
		}

		if(!group->nmembers) {
			return fail(error, error_len, group->line, "group %s has no members", group->name);
		}
	}

	return true;
}

static bool parse_rule(policy_t *p, char *line_text, int line, char *error, size_t error_len) {
	char *fields[4] = {NULL};
	int n = 0;

	char *save = NULL;

	for(char *tok = strtok_r(line_text, ",", &save); tok && n < 4; tok = strtok_r(NULL, ",", &save)) {
		fields[n++] = trim(tok);
	}

	if(n < 2) {
		return fail(error, error_len, line, "a rule needs a type and a policy");
	}

	char *type = fields[0];

	if(!strcasecmp(type, "FINAL") || !strcasecmp(type, "MATCH")) {
		int t = lookup_target(p, fields[1]);

		if(t < 0) {
			return fail(error, error_len, line, "\"%s\" is not a node, group, DIRECT or REJECT", fields[1]);
		}

		p->final_target = t;
		return true;
	}

	if(n < 3) {
		return fail(error, error_len, line, "%s needs a value and a policy", type);
	}

	rule_t rule = {0};

	if(!strcasecmp(type, "DOMAIN")) {
		rule.type = R_DOMAIN;
	} else if(!strcasecmp(type, "DOMAIN-SUFFIX")) {
		rule.type = R_SUFFIX;
	} else if(!strcasecmp(type, "DOMAIN-KEYWORD")) {
		rule.type = R_KEYWORD;
	} else if(!strcasecmp(type, "IP-CIDR")) {
		rule.type = R_CIDR;
		rule.family = AF_INET;
	} else if(!strcasecmp(type, "IP-CIDR6")) {
		rule.type = R_CIDR;
		rule.family = AF_INET6;
	} else {
		add_warning(p, line, "%s rules are not supported and were skipped", type);
		return true;
	}

	if(rule.type == R_CIDR) {
		if(!parse_cidr(fields[1], rule.family, rule.addr, &rule.prefix)) {
			return fail(error, error_len, line, "invalid address range \"%s\"", fields[1]);
		}
	} else {
		char *pattern = fields[1];
		lowercase(pattern);

		while(*pattern == '.') {
			pattern++;
		}

		size_t len = strlen(pattern);

		while(len && pattern[len - 1] == '.') {
			pattern[--len] = 0;
		}

		if(!*pattern) {
			return fail(error, error_len, line, "empty domain");
		}

		rule.pattern = xstrdup(pattern);
	}

	rule.target = lookup_target(p, fields[2]);

	if(rule.target < 0) {
		free(rule.pattern);
		return fail(error, error_len, line, "\"%s\" is not a node, group, DIRECT or REJECT", fields[2]);
	}

	p->rules = xrealloc(p->rules, (p->nrules + 1) * sizeof(rule_t));
	p->rules[p->nrules++] = rule;
	return true;
}

void policy_free(policy_t *p) {
	if(!p) {
		return;
	}

	for(int i = 0; i < p->ntargets; i++) {
		free(p->targets[i].name);
	}

	for(int g = 0; g < p->ngroups; g++) {
		free(p->groups[g].name);
		free(p->groups[g].members);
		free(p->groups[g].member_list);
	}

	for(int r = 0; r < p->nrules; r++) {
		free(p->rules[r].pattern);
	}

	for(int i = 0; i < p->nmesh_domains; i++) {
		free(p->mesh_domains[i]);
	}

	for(int i = 0; i < p->nwarnings; i++) {
		free(p->warnings[i]);
	}

	free(p->targets);
	free(p->groups);
	free(p->rules);
	free(p->mesh_domains);
	free(p->warnings);
	free(p);
}

policy_t *policy_parse(const char *text, char *error, size_t error_len) {
	if(error && error_len) {
		*error = 0;
	}

	policy_t *p = xzalloc(sizeof(*p));
	add_target(p, K_DIRECT, "DIRECT", -1);
	add_target(p, K_REJECT, "REJECT", -1);
	p->final_target = T_DIRECT;
	parse_dnsaddr("1.1.1.1", &p->dns_server);
	parse_dnsaddr("1.1.1.1", &p->direct_dns);

	char *copy = xstrdup(text ? text : "");
	enum { S_NONE, S_GENERAL, S_GROUP, S_RULE, S_OTHER } section = S_NONE;
	bool ok = true;

	/* Groups first, so rules may refer to groups defined anywhere in the file. */
	for(int pass = 0; pass < 2 && ok; pass++) {
		char *work = xstrdup(copy);
		char *save = NULL;
		int line = 0;
		section = S_NONE;

		for(char *l = work; l && ok; l = save) {
			char *nl = strchr(l, '\n');
			save = nl ? nl + 1 : NULL;

			if(nl) {
				*nl = 0;
			}

			line++;
			char *s = trim(l);

			if(!*s || *s == '#' || *s == ';' || !strncmp(s, "//", 2)) {
				continue;
			}

			if(*s == '[') {
				if(!strcasecmp(s, "[General]")) {
					section = S_GENERAL;
				} else if(!strcasecmp(s, "[Proxy Group]")) {
					section = S_GROUP;
				} else if(!strcasecmp(s, "[Rule]")) {
					section = S_RULE;
				} else {
					section = S_OTHER;

					if(pass == 1) {
						add_warning(p, line, "section %s is ignored", s);
					}
				}

				continue;
			}

			if(pass == 0) {
				if(section == S_GROUP || section == S_GENERAL) {
					char *eq = strchr(s, '=');

					if(!eq) {
						ok = fail(error, error_len, line, "expected \"name = value\"");
						break;
					}

					*eq = 0;
					char *key = trim(s);
					char *value = trim(eq + 1);
					ok = section == S_GROUP
					     ? parse_group(p, key, value, line, error, error_len)
					     : parse_general(p, key, value, line, error, error_len);
				}
			} else if(section == S_RULE) {
				ok = parse_rule(p, s, line, error, error_len);
			} else if(section == S_NONE) {
				ok = fail(error, error_len, line, "rules must be inside a [Rule] section");
			}
		}

		free(work);

		if(pass == 0 && ok) {
			ok = resolve_groups(p, error, error_len);
		}
	}

	free(copy);

	if(!ok) {
		policy_free(p);
		return NULL;
	}

	return p;
}

/* ---------------------------------------------------------------------
   Summary for the Swift side (what to route into the tunnel)
   --------------------------------------------------------------------- */

static bool target_can_be_direct(const policy_t *p, int t, int depth) {
	if(depth > 8) {
		return false;
	}

	const target_t *target = &p->targets[t];

	if(target->kind == K_DIRECT) {
		return true;
	}

	if(target->kind != K_GROUP) {
		return false;
	}

	const group_t *g = &p->groups[target->group];

	for(int i = 0; i < g->nmembers; i++) {
		if(target_can_be_direct(p, g->members[i], depth + 1)) {
			return true;
		}
	}

	return false;
}

char *policy_summary_json(const policy_t *p) {
	strbuf_t sb = {0};
	bool final_routed = p->final_target != T_DIRECT;
	bool has_keyword = false;

	for(int r = 0; r < p->nrules; r++) {
		has_keyword |= p->rules[r].type == R_KEYWORD;
	}

	/* Keyword rules and a routed FINAL need every DNS query to pass through the responder. */
	bool capture_all = has_keyword || final_routed;

	sb_add(&sb, "{\"dns_address\":\"" POLICY_DNS_ADDRESS "\",\"fake_range\":\"" POLICY_FAKE_RANGE "\"");
	sb_printf(&sb, ",\"capture_all_dns\":%s,\"default_route\":%s", capture_all ? "true" : "false", final_routed ? "true" : "false");

	sb_add(&sb, ",\"match_domains\":[");
	bool first = true;

	for(int r = 0; r < p->nrules; r++) {
		if(p->rules[r].type == R_DOMAIN || p->rules[r].type == R_SUFFIX) {
			sb_add(&sb, first ? "" : ",");
			sb_quoted(&sb, p->rules[r].pattern);
			first = false;
		}
	}

	for(int i = 0; i < p->nmesh_domains; i++) {
		sb_add(&sb, first ? "" : ",");
		sb_quoted(&sb, p->mesh_domains[i]);
		first = false;
	}

	char addr[INET6_ADDRSTRLEN];
	char cidr[INET6_ADDRSTRLEN + 8];

	for(int pass = 0; pass < 2; pass++) {
		sb_add(&sb, pass == 0 ? "],\"include_routes\":[" : "],\"exclude_routes\":[");
		first = true;

		for(int r = 0; r < p->nrules; r++) {
			const rule_t *rule = &p->rules[r];

			if(rule->type != R_CIDR) {
				continue;
			}

			bool direct = rule->target == T_DIRECT;

			if((pass == 0) == direct) {
				continue;
			}

			inet_ntop(rule->family, rule->addr, addr, sizeof(addr));
			snprintf(cidr, sizeof(cidr), "%s/%d", addr, rule->prefix);
			sb_add(&sb, first ? "" : ",");
			sb_quoted(&sb, cidr);
			first = false;
		}
	}

	sb_add(&sb, "],\"groups\":[");

	for(int g = 0; g < p->ngroups; g++) {
		sb_add(&sb, g ? "," : "");
		sb_quoted(&sb, p->groups[g].name);
	}

	sb_add(&sb, "],\"nodes\":[");
	first = true;

	for(int t = 2; t < p->ntargets; t++) {
		if(p->targets[t].kind == K_NODE) {
			sb_add(&sb, first ? "" : ",");
			sb_quoted(&sb, p->targets[t].name);
			first = false;
		}
	}

	sb_add(&sb, "],\"warnings\":[");

	for(int i = 0; i < p->nwarnings; i++) {
		sb_add(&sb, i ? "," : "");
		sb_quoted(&sb, p->warnings[i]);
	}

	if(final_routed && p->nrules) {
		/* Domains resolved to real addresses would follow FINAL through the mesh. */
		for(int r = 0; r < p->nrules; r++) {
			if(p->rules[r].type != R_CIDR && target_can_be_direct(p, p->rules[r].target, 0)) {
				sb_add(&sb, p->nwarnings ? "," : "");
				sb_quoted(&sb, "DIRECT domain rules follow FINAL when FINAL is not DIRECT; use IP-CIDR rules to exclude addresses.");
				break;
			}
		}
	}

	sb_printf(&sb, "],\"rules\":%d,\"final\":", p->nrules);
	sb_quoted(&sb, p->targets[p->final_target].name);
	sb_add(&sb, "}");
	return sb.buf;
}

/* ---------------------------------------------------------------------
   Runtime state (tinc thread only)
   --------------------------------------------------------------------- */

#define FAKE_FIRST 256            /* 198.18.1.0 */
#define FAKE_SLOTS 8192
#define FAKE_TTL 120              /* TTL handed to apps */
#define MIN_REAL_TTL 30
#define MAX_REAL_TTL 600
#define MAX_PENDING 256
#define PENDING_TIMEOUT 6
#define RETRANSMIT_INTERVAL 1     /* the first packets to a node are lost while tinc exchanges keys */
#define MAX_RETRANSMITS 4
#define FLOW_IDLE_TCP 1800
#define FLOW_IDLE_OTHER 180
#define TIMER_INTERVAL 1

static const uint8_t fake_base[4] = {198, 18, 0, 0};
static const uint8_t dns_address[4] = {198, 18, 0, 2};

typedef struct fake_t {
	char *name;
	uint8_t real[4];
	int target;
	time_t expires;   /* real address valid until */
	time_t last_used;
	int flows;        /* flows referencing this slot */
} fake_t;

typedef struct flowkey_t {
	uint8_t proto;
	uint8_t family;
	uint16_t lport;
	uint16_t rport;
	uint8_t local[16];
	uint8_t remote[16];
} flowkey_t;

typedef struct flow_t {
	flowkey_t key;
	int fake_slot;    /* -1 if the app used a real address */
	int target;
	char *node;       /* pinned node, or NULL for normal routing */
	time_t last_used;
} flow_t;

enum { MODE_FAKE, MODE_VERBATIM };

typedef struct pending_t {
	bool used;
	int mode;
	bool direct;            /* sent on the direct socket rather than through tinc */
	uint16_t upstream_id;
	dnsaddr_t server;
	uint8_t app_addr[4];
	uint16_t app_port;
	uint16_t app_id;
	uint8_t *query;         /* the app's query up to the end of the question */
	size_t query_len;
	char name[256];
	int target;
	time_t deadline;
	uint8_t *upstream;      /* what was sent upstream, for retransmission */
	size_t upstream_len;
	char *via;              /* node it was sent through, if any */
	time_t last_sent;
	int retransmits;
} pending_t;

static policy_t *P = NULL;
static policy_io_t IO;
static fake_t fakes[FAKE_SLOTS];
static splay_tree_t *flows = NULL;
static pending_t pending[MAX_PENDING];
static uint16_t pending_port_base;
static int direct_fd = -1;
static io_t direct_io;
static timeout_t policy_timer;
static int npending = 0;

static struct {
	uint64_t dns_queries, dns_fake, dns_direct, dns_rejected, dns_failed;
	uint64_t routed_packets, rejected_packets;
} stats;

bool policy_active(void) {
	return P != NULL;
}

/* ---------------------------------------------------------------------
   Choosing a node
   --------------------------------------------------------------------- */

typedef enum { C_DIRECT, C_REJECT, C_NODE, C_UNAVAILABLE } choice_kind_t;

typedef struct choice_t {
	choice_kind_t kind;
	node_t *node;
} choice_t;

static choice_t choose(int t, int depth) {
	choice_t none = {C_UNAVAILABLE, NULL};

	if(t < 0 || t >= P->ntargets || depth > 8) {
		return none;
	}

	const target_t *target = &P->targets[t];

	switch(target->kind) {
	case K_DIRECT:
		return (choice_t) {
			C_DIRECT, NULL
		};

	case K_REJECT:
		return (choice_t) {
			C_REJECT, NULL
		};

	case K_NODE: {
		node_t *n = lookup_node(target->name);

		if(n == myself) {
			return (choice_t) {
				C_DIRECT, NULL
			};
		}

		if(n && n->status.reachable) {
			return (choice_t) {
				C_NODE, n
			};
		}

		return none;
	}

	default:
		break;
	}

	const group_t *g = &P->groups[target->group];

	if(g->type == G_FASTEST) {
		choice_t best = none;
		int best_rtt = INT_MAX;

		for(int i = 0; i < g->nmembers; i++) {
			choice_t c = choose(g->members[i], depth + 1);

			if(c.kind != C_NODE) {
				if(best.kind == C_UNAVAILABLE && c.kind != C_UNAVAILABLE) {
					best = c;
				}

				continue;
			}

			/* Prefer nodes with a measured direct UDP path, by round trip time. */
			int rtt = c.node->status.udp_confirmed && c.node->udp_ping_rtt >= 0 ? c.node->udp_ping_rtt : INT_MAX - 1;

			if(best.kind != C_NODE || rtt < best_rtt) {
				best = c;
				best_rtt = rtt;
			}
		}

		return best;
	}

	if(g->type == G_SELECT) {
		return choose(g->members[0], depth + 1);
	}

	for(int i = 0; i < g->nmembers; i++) {
		choice_t c = choose(g->members[i], depth + 1);

		if(c.kind != C_UNAVAILABLE) {
			return c;
		}
	}

	return none;
}

/* ---------------------------------------------------------------------
   Checksums
   --------------------------------------------------------------------- */

static uint16_t checksum(const uint8_t *data, size_t len, uint32_t sum) {
	for(size_t i = 0; i + 1 < len; i += 2) {
		sum += get16(data + i);
	}

	if(len & 1) {
		sum += data[len - 1] << 8;
	}

	while(sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	return (uint16_t)~sum;
}

/* RFC 1624 incremental update of the checksum at field for a changed 4-byte address. */
static void checksum_replace(uint8_t *field, const uint8_t *old, const uint8_t *new, bool udp) {
	uint16_t current = get16(field);

	if(udp && current == 0) {
		return;    /* UDP over IPv4 without checksum */
	}

	uint32_t sum = (uint16_t)~current;

	for(int i = 0; i < 4; i += 2) {
		sum += (uint16_t)~get16(old + i);
		sum += get16(new + i);
	}

	while(sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	uint16_t result = (uint16_t)~sum;

	if(udp && result == 0) {
		result = 0xffff;
	}

	put16(field, result);
}

/* Replaces the source (offset 12) or destination (16) address of an IPv4 packet. */
static void rewrite_ipv4(uint8_t *ip, size_t len, int offset, const uint8_t *addr) {
	uint8_t old[4];
	memcpy(old, ip + offset, 4);
	memcpy(ip + offset, addr, 4);
	checksum_replace(ip + 10, old, addr, false);

	size_t ihl = (ip[0] & 0xf) * 4;
	bool first_fragment = (get16(ip + 6) & 0x1fff) == 0;

	if(!first_fragment) {
		return;
	}

	if(ip[9] == IPPROTO_TCP && len >= ihl + 18) {
		checksum_replace(ip + ihl + 16, old, addr, false);
	} else if(ip[9] == IPPROTO_UDP && len >= ihl + 8) {
		checksum_replace(ip + ihl + 6, old, addr, true);
	}
}

/* Builds an IPv4/UDP packet into buf; returns its length. */
static size_t build_udp4(uint8_t *buf, size_t size, const uint8_t *src, uint16_t sport,
                         const uint8_t *dst, uint16_t dport, const uint8_t *payload, size_t plen) {
	size_t total = 28 + plen;

	if(total > size || total > 65535) {
		return 0;
	}

	memset(buf, 0, 28);
	buf[0] = 0x45;
	put16(buf + 2, total);
	put16(buf + 4, rand() & 0xffff);
	buf[8] = 64;
	buf[9] = IPPROTO_UDP;
	memcpy(buf + 12, src, 4);
	memcpy(buf + 16, dst, 4);
	put16(buf + 10, checksum(buf, 20, 0));

	uint8_t *udp = buf + 20;
	put16(udp, sport);
	put16(udp + 2, dport);
	put16(udp + 4, 8 + plen);
	memcpy(udp + 8, payload, plen);

	uint32_t pseudo = get16(src) + get16(src + 2) + get16(dst) + get16(dst + 2) + IPPROTO_UDP + 8 + plen;
	uint16_t sum = checksum(udp, 8 + plen, pseudo);
	put16(udp + 6, sum ? sum : 0xffff);
	return total;
}

/* ---------------------------------------------------------------------
   Packet parsing
   --------------------------------------------------------------------- */

typedef struct pktinfo_t {
	int family;
	uint8_t proto;
	const uint8_t *src;
	const uint8_t *dst;
	size_t l4;          /* offset of the transport header, 0 if unavailable */
	uint16_t sport, dport;
} pktinfo_t;

static bool parse_packet(const uint8_t *ip, size_t len, pktinfo_t *info) {
	memset(info, 0, sizeof(*info));

	if(len >= 20 && ip[0] >> 4 == 4) {
		size_t ihl = (ip[0] & 0xf) * 4;

		if(ihl < 20 || len < ihl) {
			return false;
		}

		info->family = AF_INET;
		info->proto = ip[9];
		info->src = ip + 12;
		info->dst = ip + 16;

		if((get16(ip + 6) & 0x1fff) == 0) {
			info->l4 = ihl;
		}
	} else if(len >= 40 && ip[0] >> 4 == 6) {
		info->family = AF_INET6;
		info->proto = ip[6];   /* extension headers are not followed */
		info->src = ip + 8;
		info->dst = ip + 24;
		info->l4 = 40;
	} else {
		return false;
	}

	if(info->l4) {
		const uint8_t *l4 = ip + info->l4;
		size_t l4len = len - info->l4;

		if((info->proto == IPPROTO_TCP || info->proto == IPPROTO_UDP) && l4len >= 4) {
			info->sport = get16(l4);
			info->dport = get16(l4 + 2);
		} else if(info->proto == IPPROTO_ICMP && l4len >= 8 && (l4[0] == 8 || l4[0] == 0)) {
			info->sport = info->dport = get16(l4 + 4);    /* echo identifier */
		} else if(info->proto == 58 && l4len >= 8 && (l4[0] == 128 || l4[0] == 129)) {
			info->sport = info->dport = get16(l4 + 4);
		}
	}

	return true;
}

/* ---------------------------------------------------------------------
   Flows
   --------------------------------------------------------------------- */

static int flow_compare(const void *a, const void *b) {
	return memcmp(&((const flow_t *)a)->key, &((const flow_t *)b)->key, sizeof(flowkey_t));
}

static void flow_free(const void *data) {
	flow_t *f = (flow_t *)data;

	if(f->fake_slot >= 0 && fakes[f->fake_slot].flows > 0) {
		fakes[f->fake_slot].flows--;
	}

	free(f->node);
	free(f);
}

static void make_key(flowkey_t *key, const pktinfo_t *info, const uint8_t *local, uint16_t lport, const uint8_t *remote, uint16_t rport) {
	memset(key, 0, sizeof(*key));
	size_t alen = info->family == AF_INET ? 4 : 16;
	key->proto = info->proto;
	key->family = info->family;
	key->lport = lport;
	key->rport = rport;
	memcpy(key->local, local, alen);
	memcpy(key->remote, remote, alen);
}

static flow_t *flow_find(const flowkey_t *key) {
	if(!flows) {
		return NULL;
	}

	flow_t probe;
	probe.key = *key;
	return splay_search(flows, &probe);
}

/* Finds or creates the flow and returns the node it is pinned to (NULL: normal routing).
   Returns false if the policy rejects the flow. */
static bool flow_route(const flowkey_t *key, int target, int fake_slot, node_t **via) {
	flow_t *f = flow_find(key);
	*via = NULL;

	if(f && f->node) {
		node_t *n = lookup_node(f->node);

		if(n && n->status.reachable) {
			f->last_used = now.tv_sec;
			*via = n;
			return true;
		}
	} else if(f) {
		f->last_used = now.tv_sec;
		return true;
	}

	/* New flow, or its node went away: choose again. */
	choice_t c = choose(target, 0);

	if(c.kind == C_REJECT) {
		return false;
	}

	if(!f) {
		f = xzalloc(sizeof(*f));
		f->key = *key;
		f->fake_slot = fake_slot;
		f->target = target;

		if(fake_slot >= 0) {
			fakes[fake_slot].flows++;
		}

		splay_insert(flows, f);
	}

	free(f->node);
	f->node = c.kind == C_NODE ? xstrdup(c.node->name) : NULL;
	f->last_used = now.tv_sec;
	*via = c.kind == C_NODE ? c.node : NULL;

	if(c.kind == C_NODE) {
		logger(DEBUG_TRAFFIC, LOG_DEBUG, "Policy: new flow via %s", c.node->name);
	}

	return true;
}

/* ---------------------------------------------------------------------
   Rule matching
   --------------------------------------------------------------------- */

static bool suffix_match(const char *name, const char *suffix) {
	size_t nl = strlen(name), sl = strlen(suffix);

	if(nl == sl) {
		return !strcmp(name, suffix);
	}

	return nl > sl && name[nl - sl - 1] == '.' && !strcmp(name + nl - sl, suffix);
}

static const rule_t *match_name(const char *name) {
	for(int r = 0; r < P->nrules; r++) {
		const rule_t *rule = &P->rules[r];

		switch(rule->type) {
		case R_DOMAIN:
			if(!strcmp(name, rule->pattern)) {
				return rule;
			}

			break;

		case R_SUFFIX:
			if(suffix_match(name, rule->pattern)) {
				return rule;
			}

			break;

		case R_KEYWORD:
			if(strstr(name, rule->pattern)) {
				return rule;
			}

			break;

		default:
			break;
		}
	}

	return NULL;
}

static int match_address(int family, const uint8_t *addr) {
	for(int r = 0; r < P->nrules; r++) {
		const rule_t *rule = &P->rules[r];

		if(rule->type == R_CIDR && rule->family == family && prefix_match(addr, rule->addr, rule->prefix)) {
			return rule->target;
		}
	}

	return -1;
}

/* True if a mesh node announces a specific (non-default) Subnet containing addr. */
static bool is_mesh_address(int family, const uint8_t *addr) {
	subnet_t *s;

	if(family == AF_INET) {
		ipv4_t a;
		memcpy(&a, addr, 4);
		s = lookup_subnet_ipv4(&a);
		return s && s->owner && s->net.ipv4.prefixlength > 0;
	}

	ipv6_t a;
	memcpy(&a, addr, 16);
	s = lookup_subnet_ipv6(&a);
	return s && s->owner && s->net.ipv6.prefixlength > 0;
}

/* ---------------------------------------------------------------------
   Fake addresses
   --------------------------------------------------------------------- */

static void fake_address(int slot, uint8_t *out) {
	uint32_t v = (uint32_t)(FAKE_FIRST + slot);
	memcpy(out, fake_base, 4);
	out[2] = (uint8_t)(v >> 8);
	out[3] = (uint8_t)(v & 0xff);
}

static int fake_slot_of(const uint8_t *addr) {
	if(addr[0] != fake_base[0] || (addr[1] & 0xfe) != fake_base[1]) {
		return -2;    /* not in 198.18.0.0/15 */
	}

	uint32_t offset = ((uint32_t)(addr[1] & 1) << 16) | (uint32_t)addr[2] << 8 | addr[3];

	if(offset < FAKE_FIRST || offset >= FAKE_FIRST + FAKE_SLOTS) {
		return -1;
	}

	return (int)(offset - FAKE_FIRST);
}

static int fake_find(const char *name) {
	for(int i = 0; i < FAKE_SLOTS; i++) {
		if(fakes[i].name && !strcmp(fakes[i].name, name)) {
			return i;
		}
	}

	return -1;
}

static int fake_assign(const char *name, const uint8_t *real, int target, uint32_t ttl) {
	int slot = fake_find(name);

	if(slot < 0) {
		/* An unused slot, else the least recently used one without live flows. */
		int lru = -1;

		for(int i = 0; i < FAKE_SLOTS; i++) {
			if(!fakes[i].name) {
				slot = i;
				break;
			}

			if(!fakes[i].flows && (lru < 0 || fakes[i].last_used < fakes[lru].last_used)) {
				lru = i;
			}
		}

		if(slot < 0) {
			slot = lru >= 0 ? lru : rand() % FAKE_SLOTS;
		}

		free(fakes[slot].name);
		fakes[slot].name = xstrdup(name);
		fakes[slot].flows = 0;
	}

	if(ttl < MIN_REAL_TTL) {
		ttl = MIN_REAL_TTL;
	} else if(ttl > MAX_REAL_TTL) {
		ttl = MAX_REAL_TTL;
	}

	memcpy(fakes[slot].real, real, 4);
	fakes[slot].target = target;
	fakes[slot].expires = now.tv_sec + ttl;
	fakes[slot].last_used = now.tv_sec;
	return slot;
}

/* ---------------------------------------------------------------------
   DNS
   --------------------------------------------------------------------- */

#define DNS_A 1
#define DNS_AAAA 28
#define DNS_SVCB 64
#define DNS_HTTPS 65
#define RCODE_SERVFAIL 2
#define RCODE_NXDOMAIN 3

/* Parses a single-question query. Returns the offset just past the question. */
static size_t dns_parse_query(const uint8_t *dns, size_t len, char *name, size_t namelen, uint16_t *qtype) {
	if(len < 12 || (dns[2] & 0x80) || get16(dns + 4) != 1) {
		return 0;
	}

	size_t off = 12, out = 0;

	while(off < len && dns[off]) {
		uint8_t l = dns[off++];

		if(l > 63 || off + l > len || out + l + 2 > namelen) {
			return 0;
		}

		if(out) {
			name[out++] = '.';
		}

		for(int i = 0; i < l; i++) {
			name[out++] = tolower(dns[off + i]);
		}

		off += l;
	}

	if(off + 5 > len) {
		return 0;
	}

	name[out] = 0;
	off++;
	*qtype = get16(dns + off);
	return off + 4;
}

static size_t dns_skip_name(const uint8_t *dns, size_t len, size_t off) {
	while(off < len) {
		uint8_t l = dns[off];

		if((l & 0xc0) == 0xc0) {
			return off + 2;
		}

		if(!l) {
			return off + 1;
		}

		off += l + 1;
	}

	return 0;
}

/* Finds the first A record in a response. Returns the rcode, or -1 if malformed. */
static int dns_first_a(const uint8_t *dns, size_t len, uint8_t *addr, uint32_t *ttl, bool *found) {
	*found = false;

	if(len < 12) {
		return -1;
	}

	int rcode = dns[3] & 0xf;
	size_t off = 12;

	for(int q = get16(dns + 4); q > 0; q--) {
		off = dns_skip_name(dns, len, off);

		if(!off || off + 4 > len) {
			return -1;
		}

		off += 4;
	}

	for(int a = get16(dns + 6); a > 0; a--) {
		off = dns_skip_name(dns, len, off);

		if(!off || off + 10 > len) {
			return -1;
		}

		uint16_t type = get16(dns + off);
		uint32_t rttl = (uint32_t)get16(dns + off + 4) << 16 | get16(dns + off + 6);
		uint16_t rdlen = get16(dns + off + 8);
		off += 10;

		if(off + rdlen > len) {
			return -1;
		}

		if(type == DNS_A && rdlen == 4 && !*found) {
			memcpy(addr, dns + off, 4);
			*ttl = rttl;
			*found = true;
		}

		off += rdlen;
	}

	return rcode;
}

/* Builds an answer to the app's query (header and question), optionally with one A record. */
static size_t dns_build_answer(uint8_t *out, size_t size, const uint8_t *query, size_t qlen, int rcode, const uint8_t *a, uint32_t ttl) {
	if(qlen + 16 > size) {
		return 0;
	}

	memcpy(out, query, qlen);
	uint16_t flags = 0x8000 | (get16(query + 2) & 0x7900) | 0x0080 | (rcode & 0xf);
	put16(out + 2, flags);
	put16(out + 4, 1);
	put16(out + 6, a ? 1 : 0);
	put16(out + 8, 0);
	put16(out + 10, 0);

	if(!a) {
		return qlen;
	}

	uint8_t *rr = out + qlen;
	put16(rr, 0xc00c);      /* pointer to the question name */
	put16(rr + 2, DNS_A);
	put16(rr + 4, 1);
	put32(rr + 6, ttl);
	put16(rr + 10, 4);
	memcpy(rr + 12, a, 4);
	return qlen + 16;
}

static void reply_to_app(const uint8_t *app_addr, uint16_t app_port, const uint8_t *dns, size_t dnslen) {
	uint8_t pkt[1600];
	size_t len = build_udp4(pkt, sizeof(pkt), dns_address, 53, app_addr, app_port, dns, dnslen);

	if(len && IO.write_to_app) {
		IO.write_to_app(pkt, len);
	}
}

static void answer_app(const uint8_t *app_addr, uint16_t app_port, const uint8_t *query, size_t qlen,
                       int rcode, const uint8_t *a, uint32_t ttl) {
	uint8_t dns[600];
	size_t len = dns_build_answer(dns, sizeof(dns), query, qlen, rcode, a, ttl);

	if(len) {
		reply_to_app(app_addr, app_port, dns, len);
	}
}

static void pending_release(pending_t *q) {
	free(q->query);
	free(q->upstream);
	free(q->via);
	memset(q, 0, sizeof(*q));
	npending--;
}

static bool open_direct_socket(int family) {
	if(direct_fd >= 0) {
		return true;
	}

	direct_fd = socket(family, SOCK_DGRAM, 0);

	if(direct_fd < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Policy: could not open DNS socket: %s", strerror(errno));
		return false;
	}

	fcntl(direct_fd, F_SETFL, fcntl(direct_fd, F_GETFL) | O_NONBLOCK);
#ifdef FD_CLOEXEC
	fcntl(direct_fd, F_SETFD, FD_CLOEXEC);
#endif
	return true;
}

static void handle_upstream_answer(pending_t *q, uint8_t *dns, size_t len) {
	if(q->mode == MODE_FAKE) {
		uint8_t real[4];
		uint32_t ttl = 0;
		bool found;
		int rcode = dns_first_a(dns, len, real, &ttl, &found);

		if(rcode == 0 && found) {
			int slot = fake_assign(q->name, real, q->target, ttl);
			uint8_t fake[4];
			fake_address(slot, fake);
			stats.dns_fake++;
			logger(DEBUG_TRAFFIC, LOG_DEBUG, "Policy: %s -> fake %d.%d.%d.%d (real %d.%d.%d.%d)", q->name,
			       fake[0], fake[1], fake[2], fake[3], real[0], real[1], real[2], real[3]);
			answer_app(q->app_addr, q->app_port, q->query, q->query_len, 0, fake, FAKE_TTL);
			pending_release(q);
			return;
		}
	}

	/* Relay the upstream answer unchanged, under the app's query ID. */
	put16(dns, q->app_id);
	reply_to_app(q->app_addr, q->app_port, dns, len);
	pending_release(q);
}

static void direct_socket_handler(void *data, int flags) {
	(void)data;
	(void)flags;
	uint8_t buf[4096];

	for(;;) {
		ssize_t len = recv(direct_fd, buf, sizeof(buf), 0);

		if(len < 0) {
			return;
		}

		if(len < 12) {
			continue;
		}

		uint16_t id = get16(buf);

		for(int i = 0; i < MAX_PENDING; i++) {
			if(pending[i].used && pending[i].direct && pending[i].upstream_id == id) {
				handle_upstream_answer(&pending[i], buf, len);
				break;
			}
		}
	}
}

static bool send_direct(const pending_t *q) {
	if(!open_direct_socket(q->server.family)) {
		return false;
	}

	if(!direct_io.cb) {
		io_add(&direct_io, direct_socket_handler, NULL, direct_fd, IO_READ);
	}

	struct sockaddr_storage ss = {0};
	socklen_t sslen;

	if(q->server.family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
		sin->sin_family = AF_INET;
		sin->sin_port = htons(q->server.port);
		memcpy(&sin->sin_addr, q->server.addr, 4);
		sslen = sizeof(*sin);
	} else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons(q->server.port);
		memcpy(&sin6->sin6_addr, q->server.addr, 16);
		sslen = sizeof(*sin6);
	}

	return sendto(direct_fd, q->upstream, q->upstream_len, 0, (struct sockaddr *)&ss, sslen) >= 0;
}

/* (Re)sends a pending query. Returns false if it could not be sent at all. */
static bool pending_send(pending_t *q) {
	q->last_sent = now.tv_sec;

	if(q->direct) {
		return send_direct(q);
	}

	node_t *via = NULL;

	if(q->via) {
		via = lookup_node(q->via);

		if(!via || !via->status.reachable) {
			return false;
		}
	}

	if(IO.inject) {
		IO.inject(q->upstream, q->upstream_len, via);
	}

	return true;
}

/* Sends the app's query upstream: directly, or through the mesh (optionally via a node). */
static void forward_query(const pktinfo_t *info, const uint8_t *dns, size_t dnslen, size_t qlen,
                          const char *name, int mode, int target, const dnsaddr_t *server, bool direct, node_t *via) {
	int slot = -1;

	for(int i = 0; i < MAX_PENDING; i++) {
		if(!pending[i].used) {
			slot = i;
			break;
		}
	}

	if(slot < 0 || !server->set) {
		stats.dns_failed++;
		answer_app(info->src, info->sport, dns, qlen, RCODE_SERVFAIL, NULL, 0);
		return;
	}

	pending_t *q = &pending[slot];
	memset(q, 0, sizeof(*q));
	q->used = true;
	q->mode = mode;
	q->direct = direct;
	q->server = *server;
	q->target = target;
	q->upstream_id = rand() & 0xffff;
	q->app_id = get16(dns);
	q->app_port = info->sport;
	memcpy(q->app_addr, info->src, 4);
	q->query = xmalloc(qlen);
	memcpy(q->query, dns, qlen);
	q->query_len = qlen;
	snprintf(q->name, sizeof(q->name), "%s", name);
	q->deadline = now.tv_sec + PENDING_TIMEOUT;
	npending++;

	uint8_t *copy = xmalloc(dnslen);
	memcpy(copy, dns, dnslen);
	put16(copy, q->upstream_id);

	if(direct) {
		q->upstream = copy;
		q->upstream_len = dnslen;
	} else {
		/* Through the mesh, from this device's VPN address (the app's source address). */
		uint8_t pkt[1600];
		size_t len = build_udp4(pkt, sizeof(pkt), info->src, pending_port_base + slot, server->addr, server->port, copy, dnslen);
		free(copy);
		q->upstream = xmalloc(len ? len : 1);
		memcpy(q->upstream, pkt, len);
		q->upstream_len = len;
		q->via = via ? xstrdup(via->name) : NULL;
	}

	if(!q->upstream_len || !pending_send(q)) {
		stats.dns_failed++;
		answer_app(q->app_addr, q->app_port, q->query, q->query_len, RCODE_SERVFAIL, NULL, 0);
		pending_release(q);
	}
}

static bool name_in_mesh_domains(const char *name) {
	for(int i = 0; i < P->nmesh_domains; i++) {
		if(suffix_match(name, P->mesh_domains[i])) {
			return true;
		}
	}

	return false;
}

static void handle_app_query(const uint8_t *ip, size_t len, const pktinfo_t *info) {
	const uint8_t *udp = ip + info->l4;
	size_t udplen = get16(udp + 4);

	if(udplen < 8 || info->l4 + udplen > len) {
		return;
	}

	const uint8_t *dns = udp + 8;
	size_t dnslen = udplen - 8;
	char name[256];
	uint16_t qtype;
	size_t qlen = dns_parse_query(dns, dnslen, name, sizeof(name), &qtype);

	if(!qlen) {
		return;
	}

	stats.dns_queries++;

	/* Names inside the mesh go to the mesh's own DNS server by normal routing. */
	if(P->mesh_dns.set && P->mesh_dns.family == AF_INET && (name_in_mesh_domains(name) || !P->nmesh_domains)) {
		if(name_in_mesh_domains(name) || !match_name(name)) {
			forward_query(info, dns, dnslen, qlen, name, MODE_VERBATIM, T_DIRECT, &P->mesh_dns, false, NULL);
			return;
		}
	}

	const rule_t *rule = match_name(name);
	choice_t c = rule ? choose(rule->target, 0) : (choice_t) {
		C_DIRECT, NULL
	};

	switch(c.kind) {
	case C_REJECT:
		stats.dns_rejected++;
		answer_app(info->src, info->sport, dns, qlen, RCODE_NXDOMAIN, NULL, 0);
		return;

	case C_UNAVAILABLE:
		/* Like a proxy client with its proxy down: fail rather than leak to another path. */
		stats.dns_failed++;
		logger(DEBUG_CONNECTIONS, LOG_WARNING, "Policy: no reachable node for %s", name);
		answer_app(info->src, info->sport, dns, qlen, RCODE_SERVFAIL, NULL, 0);
		return;

	case C_DIRECT:
		stats.dns_direct++;
		forward_query(info, dns, dnslen, qlen, name, MODE_VERBATIM, T_DIRECT, &P->direct_dns, true, NULL);
		return;

	case C_NODE:
		break;
	}

	if(qtype == DNS_A) {
		/* Reuse a recent resolution of this name. */
		int slot = fake_find(name);

		if(slot >= 0 && fakes[slot].target == rule->target && fakes[slot].expires > now.tv_sec) {
			uint8_t fake[4];
			fake_address(slot, fake);
			fakes[slot].last_used = now.tv_sec;
			stats.dns_fake++;
			answer_app(info->src, info->sport, dns, qlen, 0, fake, FAKE_TTL);
			return;
		}

		forward_query(info, dns, dnslen, qlen, name, MODE_FAKE, rule->target, &P->dns_server, false, c.node);
	} else if(qtype == DNS_AAAA || qtype == DNS_HTTPS || qtype == DNS_SVCB) {
		/* No real IPv6 or address hints for routed names: everything goes through the fake IPv4. */
		answer_app(info->src, info->sport, dns, qlen, 0, NULL, 0);
	} else {
		forward_query(info, dns, dnslen, qlen, name, MODE_VERBATIM, rule->target, &P->dns_server, false, c.node);
	}
}

/* ---------------------------------------------------------------------
   Packet hooks
   --------------------------------------------------------------------- */

policy_verdict_t policy_outbound(uint8_t *ip, size_t len, node_t **via) {
	*via = NULL;

	if(!P) {
		return POLICY_FORWARD;
	}

	pktinfo_t info;

	if(!parse_packet(ip, len, &info)) {
		return POLICY_FORWARD;
	}

	if(info.family == AF_INET && !memcmp(info.dst, dns_address, 4)) {
		if(info.proto == IPPROTO_UDP && info.l4 && info.dport == 53 && len >= info.l4 + 8) {
			handle_app_query(ip, len, &info);
		}

		return POLICY_CONSUMED;
	}

	if(info.family == AF_INET) {
		int slot = fake_slot_of(info.dst);

		if(slot == -1 || (slot >= 0 && !fakes[slot].name)) {
			return POLICY_CONSUMED;    /* unassigned fake address */
		}

		if(slot >= 0) {
			fake_t *fake = &fakes[slot];
			fake->last_used = now.tv_sec;
			flowkey_t key;
			make_key(&key, &info, info.src, info.sport, fake->real, info.dport);

			if(!flow_route(&key, fake->target, slot, via)) {
				stats.rejected_packets++;
				return POLICY_CONSUMED;
			}

			rewrite_ipv4(ip, len, 16, fake->real);
			stats.routed_packets++;
			return POLICY_FORWARD;
		}
	}

	int target = match_address(info.family, info.dst);

	if(target < 0) {
		if(P->final_target == T_DIRECT || is_mesh_address(info.family, info.dst)) {
			return POLICY_FORWARD;
		}

		target = P->final_target;
	}

	if(target == T_DIRECT) {
		return POLICY_FORWARD;
	}

	flowkey_t key;
	make_key(&key, &info, info.src, info.sport, info.dst, info.dport);

	if(!flow_route(&key, target, -1, via)) {
		stats.rejected_packets++;
		return POLICY_CONSUMED;
	}

	stats.routed_packets++;
	return POLICY_FORWARD;
}

policy_verdict_t policy_inbound(uint8_t *ip, size_t len) {
	if(!P) {
		return POLICY_FORWARD;
	}

	pktinfo_t info;

	if(!parse_packet(ip, len, &info)) {
		return POLICY_FORWARD;
	}

	/* Answers to queries this engine sent through the mesh. */
	if(info.family == AF_INET && info.proto == IPPROTO_UDP && info.l4 && npending
	                && info.dport >= pending_port_base && info.dport < pending_port_base + MAX_PENDING) {
		pending_t *q = &pending[info.dport - pending_port_base];
		const uint8_t *udp = ip + info.l4;
		size_t udplen = get16(udp + 4);

		if(q->used && !q->direct && info.sport == q->server.port && !memcmp(info.src, q->server.addr, 4)
		                && udplen >= 20 && info.l4 + udplen <= len && get16(udp + 8) == q->upstream_id) {
			handle_upstream_answer(q, (uint8_t *)udp + 8, udplen - 8);
			return POLICY_CONSUMED;
		}
	}

	if(info.family == AF_INET && flows && flows->head) {
		flowkey_t key;
		make_key(&key, &info, info.dst, info.dport, info.src, info.sport);
		flow_t *f = flow_find(&key);

		if(f) {
			f->last_used = now.tv_sec;

			if(f->fake_slot >= 0) {
				uint8_t fake[4];
				fake_address(f->fake_slot, fake);
				rewrite_ipv4(ip, len, 12, fake);
			}
		}
	}

	return POLICY_FORWARD;
}

/* ---------------------------------------------------------------------
   Housekeeping
   --------------------------------------------------------------------- */

static void policy_timer_handler(void *data) {
	(void)data;

	for(int i = 0; i < MAX_PENDING; i++) {
		pending_t *q = &pending[i];

		if(!q->used) {
			continue;
		}

		if(q->deadline <= now.tv_sec) {
			stats.dns_failed++;
			logger(DEBUG_CONNECTIONS, LOG_WARNING, "Policy: DNS query for %s timed out", q->name);
			answer_app(q->app_addr, q->app_port, q->query, q->query_len, RCODE_SERVFAIL, NULL, 0);
			pending_release(q);
		} else if(q->retransmits < MAX_RETRANSMITS && now.tv_sec - q->last_sent >= RETRANSMIT_INTERVAL) {
			q->retransmits++;
			pending_send(q);
		}
	}

	if(flows) {
		for splay_each(flow_t, f, flows) {
			int idle = f->key.proto == IPPROTO_TCP ? FLOW_IDLE_TCP : FLOW_IDLE_OTHER;

			if(now.tv_sec - f->last_used > idle) {
				splay_delete(flows, f);
			}
		}
	}

	timeout_set(&policy_timer, &(struct timeval) {
		TIMER_INTERVAL, 0
	});
}

static void reset_state(void) {
	if(flows) {
		splay_delete_tree(flows);
		flows = NULL;
	}

	for(int i = 0; i < MAX_PENDING; i++) {
		if(pending[i].used) {
			free(pending[i].query);
		}
	}

	memset(pending, 0, sizeof(pending));
	npending = 0;

	for(int i = 0; i < FAKE_SLOTS; i++) {
		free(fakes[i].name);
	}

	memset(fakes, 0, sizeof(fakes));

	if(direct_io.cb) {
		io_del(&direct_io);
	}

	if(direct_fd >= 0) {
		close(direct_fd);
		direct_fd = -1;
	}

	memset(&stats, 0, sizeof(stats));
}

void policy_install(policy_t *policy, const policy_io_t *io) {
	reset_state();
	policy_free(P);
	P = policy;

	if(io) {
		IO = *io;
	}

	if(!P) {
		timeout_del(&policy_timer);
		logger(DEBUG_ALWAYS, LOG_NOTICE, "Policy routing disabled");
		return;
	}

	flows = splay_alloc_tree(flow_compare, flow_free);
	pending_port_base = 40000 + (rand() % 20000);

	if(!policy_timer.cb) {
		timeout_add(&policy_timer, policy_timer_handler, NULL, &(struct timeval) {
			TIMER_INTERVAL, 0
		});
	}

	logger(DEBUG_ALWAYS, LOG_NOTICE, "Policy routing enabled: %d rules, %d groups, FINAL %s",
	       P->nrules, P->ngroups, P->targets[P->final_target].name);
}

void policy_shutdown(void) {
	reset_state();
	timeout_del(&policy_timer);
	policy_free(P);
	P = NULL;
}

char *policy_status_json(void) {
	strbuf_t sb = {0};

	if(!P) {
		sb_add(&sb, "{\"enabled\":false}");
		return sb.buf;
	}

	int nflows = 0, nfakes = 0;

	if(flows) {
		for splay_each(flow_t, f, flows) {
			(void)f;
			nflows++;
		}
	}

	for(int i = 0; i < FAKE_SLOTS; i++) {
		nfakes += fakes[i].name != NULL;
	}

	sb_printf(&sb, "{\"enabled\":true,\"rules\":%d,\"flows\":%d,\"fake_ips\":%d,\"dns_pending\":%d", P->nrules, nflows, nfakes, npending);
	sb_printf(&sb, ",\"dns_queries\":%llu,\"dns_fake\":%llu,\"dns_direct\":%llu,\"dns_rejected\":%llu,\"dns_failed\":%llu",
	          (unsigned long long)stats.dns_queries, (unsigned long long)stats.dns_fake, (unsigned long long)stats.dns_direct,
	          (unsigned long long)stats.dns_rejected, (unsigned long long)stats.dns_failed);
	sb_printf(&sb, ",\"routed_packets\":%llu,\"rejected_packets\":%llu",
	          (unsigned long long)stats.routed_packets, (unsigned long long)stats.rejected_packets);
	sb_add(&sb, ",\"groups\":[");

	for(int g = 0; g < P->ngroups; g++) {
		int t = -1;

		for(int i = 2; i < P->ntargets; i++) {
			if(P->targets[i].kind == K_GROUP && P->targets[i].group == g) {
				t = i;
			}
		}

		choice_t c = t >= 0 ? choose(t, 0) : (choice_t) {
			C_UNAVAILABLE, NULL
		};
		const char *selected = c.kind == C_NODE ? c.node->name : c.kind == C_DIRECT ? "DIRECT" : c.kind == C_REJECT ? "REJECT" : NULL;
		sb_add(&sb, g ? ",{\"name\":" : "{\"name\":");
		sb_quoted(&sb, P->groups[g].name);
		sb_add(&sb, ",\"selected\":");

		if(selected) {
			sb_quoted(&sb, selected);
		} else {
			sb_add(&sb, "null");
		}

		sb_add(&sb, "}");
	}

	sb_add(&sb, "]}");
	return sb.buf;
}
