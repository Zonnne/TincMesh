/*
    tinc_join.c -- `tinc join` for iOS

    A port of cmd_join()/finalize_join() from tinc's invitation.c. The
    wire protocol and the files written are the same as the tinc CLI's,
    but this version keeps its state in a context struct, never reads
    stdin, never generates or runs a tinc-up script, and reports the
    invitation's Ifconfig/Route statements back to the caller so the app
    can apply them as NEPacketTunnelNetworkSettings.

    Copyright (C) 2013-2021 Guus Sliepen <guus@tinc-vpn.org> (invitation.c)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "../tinc/system.h"

#include <poll.h>

#include "../tinc/crypto.h"
#include "../tinc/ecdsa.h"
#include "../tinc/ecdsagen.h"
#include "../tinc/ed25519/sha512.h"
#include "../tinc/netutl.h"
#include "../tinc/protocol.h"
#include "../tinc/sptps.h"
#include "../tinc/utils.h"
#include "../tinc/xalloc.h"

#include "tinc_ios.h"
#include "tinc_ios_util.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

/* From tincctl.h/tincctl.c: which variables an invitation may set, and where they go. */
#define VAR_SERVER 1    /* Should be in tinc.conf */
#define VAR_HOST 2      /* Can be in host config file */
#define VAR_MULTIPLE 4  /* Multiple statements allowed */
#define VAR_OBSOLETE 8  /* Should not be used anymore */
#define VAR_SAFE 16     /* Variable is safe when accepting invitations */

static const struct {
	const char *name;
	int type;
} variables[] = {
	/* Server configuration */
	{"AddressFamily", VAR_SERVER | VAR_SAFE},
	{"AutoConnect", VAR_SERVER | VAR_SAFE},
	{"BindToAddress", VAR_SERVER | VAR_MULTIPLE},
	{"BindToInterface", VAR_SERVER},
	{"Broadcast", VAR_SERVER | VAR_SAFE},
	{"BroadcastSubnet", VAR_SERVER | VAR_MULTIPLE | VAR_SAFE},
	{"ConnectTo", VAR_SERVER | VAR_MULTIPLE | VAR_SAFE},
	{"DecrementTTL", VAR_SERVER | VAR_SAFE},
	{"Device", VAR_SERVER},
	{"DeviceStandby", VAR_SERVER},
	{"DeviceType", VAR_SERVER},
	{"DirectOnly", VAR_SERVER | VAR_SAFE},
	{"Ed25519PrivateKeyFile", VAR_SERVER},
	{"ExperimentalProtocol", VAR_SERVER},
	{"Forwarding", VAR_SERVER},
	{"FWMark", VAR_SERVER},
	{"GraphDumpFile", VAR_SERVER | VAR_OBSOLETE},
	{"Hostnames", VAR_SERVER},
	{"IffOneQueue", VAR_SERVER},
	{"Interface", VAR_SERVER},
	{"InvitationExpire", VAR_SERVER},
	{"KeyExpire", VAR_SERVER | VAR_SAFE},
	{"ListenAddress", VAR_SERVER | VAR_MULTIPLE},
	{"LocalDiscovery", VAR_SERVER | VAR_SAFE},
	{"LogLevel", VAR_SERVER},
	{"MACExpire", VAR_SERVER | VAR_SAFE},
	{"MaxConnectionBurst", VAR_SERVER | VAR_SAFE},
	{"MaxOutputBufferSize", VAR_SERVER | VAR_SAFE},
	{"MaxTimeout", VAR_SERVER | VAR_SAFE},
	{"Mode", VAR_SERVER | VAR_SAFE},
	{"Name", VAR_SERVER},
	{"PingInterval", VAR_SERVER | VAR_SAFE},
	{"PingTimeout", VAR_SERVER | VAR_SAFE},
	{"PriorityInheritance", VAR_SERVER},
	{"PrivateKey", VAR_SERVER | VAR_OBSOLETE},
	{"PrivateKeyFile", VAR_SERVER},
	{"ProcessPriority", VAR_SERVER},
	{"Proxy", VAR_SERVER},
	{"ReplayWindow", VAR_SERVER | VAR_SAFE},
	{"ScriptsExtension", VAR_SERVER},
	{"ScriptsInterpreter", VAR_SERVER},
	{"StrictSubnets", VAR_SERVER | VAR_SAFE},
	{"TunnelServer", VAR_SERVER | VAR_SAFE},
	{"UDPDiscovery", VAR_SERVER | VAR_SAFE},
	{"UDPDiscoveryKeepaliveInterval", VAR_SERVER | VAR_SAFE},
	{"UDPDiscoveryInterval", VAR_SERVER | VAR_SAFE},
	{"UDPDiscoveryTimeout", VAR_SERVER | VAR_SAFE},
	{"MTUInfoInterval", VAR_SERVER | VAR_SAFE},
	{"UDPInfoInterval", VAR_SERVER | VAR_SAFE},
	{"UDPRcvBuf", VAR_SERVER},
	{"UDPSndBuf", VAR_SERVER},
	{"UPnP", VAR_SERVER},
	{"UPnPDiscoverWait", VAR_SERVER},
	{"UPnPRefreshPeriod", VAR_SERVER},
	{"VDEGroup", VAR_SERVER},
	{"VDEPort", VAR_SERVER},
	/* Host configuration */
	{"Address", VAR_HOST | VAR_MULTIPLE},
	{"Cipher", VAR_SERVER | VAR_HOST},
	{"ClampMSS", VAR_SERVER | VAR_HOST | VAR_SAFE},
	{"Compression", VAR_SERVER | VAR_HOST | VAR_SAFE},
	{"Digest", VAR_SERVER | VAR_HOST},
	{"Ed25519PublicKey", VAR_HOST},
	{"Ed25519PublicKeyFile", VAR_SERVER | VAR_HOST},
	{"IndirectData", VAR_SERVER | VAR_HOST | VAR_SAFE},
	{"MACLength", VAR_SERVER | VAR_HOST},
	{"PMTU", VAR_SERVER | VAR_HOST},
	{"PMTUDiscovery", VAR_SERVER | VAR_HOST},
	{"Port", VAR_HOST},
	{"PublicKey", VAR_HOST | VAR_OBSOLETE},
	{"PublicKeyFile", VAR_SERVER | VAR_HOST | VAR_OBSOLETE},
	{"Subnet", VAR_HOST | VAR_MULTIPLE | VAR_SAFE},
	{"TCPOnly", VAR_SERVER | VAR_HOST | VAR_SAFE},
	{"Weight", VAR_HOST | VAR_SAFE},
	{NULL, 0}
};

typedef struct join_t {
	const char *confbase;
	int sock;
	char buffer[4096];      /* bytes received but not yet consumed by recvline() */
	size_t blen;
	char cookie[18];
	char hash[18];
	sptps_t sptps;
	char *data;             /* invitation data received over SPTPS */
	size_t datalen;
	bool success;
	char name[MAX_STRING_SIZE];
	char netname[MAX_STRING_SIZE];
	char *ifconfig_json;    /* JSON array body, without brackets */
	char *routes_json;
	char *error;
	size_t error_len;
} join_t;

static void join_error(join_t *j, const char *format, ...) {
	if(!j->error || !j->error_len || *j->error) {
		return;    /* keep the first, most specific error */
	}

	va_list ap;
	va_start(ap, format);
	vsnprintf(j->error, j->error_len, format, ap);
	va_end(ap);
}

static void json_list_append(char **list, const char *value) {
	char *quoted = tinc_ios_json_quote(value);
	char *joined;
	xasprintf(&joined, "%s%s%s", *list ? *list : "", *list ? "," : "", quoted);
	free(quoted);
	free(*list);
	*list = joined;
}

/* ---------------------------------------------------------------------
   Line-based socket I/O used before SPTPS starts (from tincctl.c)
   --------------------------------------------------------------------- */

static bool recvline(join_t *j, char *line, size_t len) {
	char *newline;

	while(!(newline = memchr(j->buffer, '\n', j->blen))) {
		if(j->blen >= sizeof(j->buffer)) {
			return false;
		}

		ssize_t result = recv(j->sock, j->buffer + j->blen, sizeof(j->buffer) - j->blen, 0);

		if(result == -1 && errno == EINTR) {
			continue;
		} else if(result <= 0) {
			return false;
		}

		j->blen += result;
	}

	if((size_t)(newline - j->buffer) >= len) {
		return false;
	}

	len = newline - j->buffer;
	memcpy(line, j->buffer, len);
	line[len] = 0;
	memmove(j->buffer, newline + 1, j->blen - len - 1);
	j->blen -= len + 1;
	return true;
}

static bool send_all(int sock, const void *vdata, size_t len) {
	const char *data = vdata;

	while(len) {
		ssize_t result = send(sock, data, len, MSG_NOSIGNAL);

		if(result == -1 && errno == EINTR) {
			continue;
		} else if(result <= 0) {
			return false;
		}

		data += result;
		len -= result;
	}

	return true;
}

/* ---------------------------------------------------------------------
   Parsing helpers (from invitation.c and tincctl.c)
   --------------------------------------------------------------------- */

static char *rstrip(char *value) {
	size_t len = strlen(value);

	while(len && strchr("\t\r\n ", value[len - 1])) {
		value[--len] = 0;
	}

	return value;
}

static char *get_line(const char **data, char *line, size_t size) {
	if(!data || !*data || !**data) {
		if(data) {
			*data = NULL;
		}

		return NULL;
	}

	const char *end = strchr(*data, '\n');
	size_t len = end ? (size_t)(end - *data) : strlen(*data);

	if(len >= size) {
		return NULL;
	}

	memcpy(line, *data, len);
	line[len] = 0;

	/* Tolerate CRLF line endings. */
	if(len && line[len - 1] == '\r') {
		line[len - 1] = 0;
	}

	*data = end ? end + 1 : NULL;
	return line;
}

/* Splits "Variable = Value" in place; returns the value. */
static char *split_variable(char *line) {
	size_t len = strcspn(line, "\t =");
	char *value = line + len;
	value += strspn(value, "\t ");

	if(*value == '=') {
		value++;
		value += strspn(value, "\t ");
	}

	line[len] = 0;
	return value;
}

static bool grep_value(const char *data, const char *var, char *out, size_t outlen) {
	char line[1024];
	const char *p = data;

	while(get_line(&p, line, sizeof(line))) {
		char *value = split_variable(line);

		if(!strcasecmp(line, var)) {
			strncpy(out, value, outlen - 1);
			out[outlen - 1] = 0;
			return true;
		}
	}

	return false;
}

static FILE *open_in_confbase(join_t *j, const char *mode_desc, int perms, const char *format, ...) {
	char filename[PATH_MAX];
	char relative[PATH_MAX];
	va_list ap;
	va_start(ap, format);
	vsnprintf(relative, sizeof(relative), format, ap);
	va_end(ap);
	snprintf(filename, sizeof(filename), "%s" SLASH "%s", j->confbase, relative);

	/* open() with explicit permissions instead of umask(), which is process-wide. */
	int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, perms);
	FILE *f = fd >= 0 ? fdopen(fd, "w") : NULL;

	if(!f) {
		join_error(j, "Could not create %s %s: %s", mode_desc, relative, strerror(errno));

		if(fd >= 0) {
			close(fd);
		}
	}

	return f;
}

/* ---------------------------------------------------------------------
   Writing the configuration
   --------------------------------------------------------------------- */

static bool finalize_join(join_t *j) {
	char line[1024];
	char *value = NULL;
	const char *p = j->data;

	/* The first line must name us. */
	if(!get_line(&p, line, sizeof(line))) {
		join_error(j, "No Name found in invitation");
		return false;
	}

	value = split_variable(line);

	if(strcasecmp(line, "Name") || !check_id(value)) {
		join_error(j, "No valid Name found in invitation");
		return false;
	}

	strncpy(j->name, value, sizeof(j->name) - 1);

	char netname[MAX_STRING_SIZE] = "";

	if(grep_value(j->data, "NetName", netname, sizeof(netname))) {
		if(check_netname(netname, true)) {
			strncpy(j->netname, netname, sizeof(j->netname) - 1);
		}
	}

	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s" SLASH "tinc.conf", j->confbase);

	if(!access(path, F_OK)) {
		join_error(j, "Configuration file tinc.conf already exists");
		return false;
	}

	if(mkdir(j->confbase, 0700) && errno != EEXIST) {
		join_error(j, "Could not create configuration directory: %s", strerror(errno));
		return false;
	}

	snprintf(path, sizeof(path), "%s" SLASH "hosts", j->confbase);

	if(mkdir(path, 0700) && errno != EEXIST) {
		join_error(j, "Could not create hosts directory: %s", strerror(errno));
		return false;
	}

	FILE *f = open_in_confbase(j, "file", 0644, "tinc.conf");

	if(!f) {
		return false;
	}

	fprintf(f, "Name = %s\n", j->name);

	FILE *fh = open_in_confbase(j, "file", 0644, "hosts" SLASH "%s", j->name);

	if(!fh) {
		fclose(f);
		return false;
	}

	FILE *finv = open_in_confbase(j, "file", 0600, "invitation-data");

	if(finv) {
		fwrite(j->data, j->datalen, 1, finv);
		fclose(finv);
	}

	/* Filter the first chunk on approved keywords, split between tinc.conf
	   and hosts/Name. Ifconfig and Route are reported to the caller. */
	p = j->data;
	char *l;
	bool more_chunks = false;

	while((l = get_line(&p, line, sizeof(line)))) {
		if(*l == '#') {
			continue;
		}

		value = split_variable(l);

		if(!*l) {
			continue;
		}

		if(!strcasecmp(l, "Name")) {
			if(strcmp(value, j->name)) {
				more_chunks = true;
				break;
			}

			continue;
		} else if(!strcasecmp(l, "NetName")) {
			continue;
		} else if(!strcasecmp(l, "Ifconfig")) {
			json_list_append(&j->ifconfig_json, value);
			continue;
		} else if(!strcasecmp(l, "Route")) {
			json_list_append(&j->routes_json, value);
			continue;
		}

		int i;

		for(i = 0; variables[i].name; i++) {
			if(!strcasecmp(l, variables[i].name)) {
				break;
			}
		}

		if(!variables[i].name) {
			fprintf(stderr, "Ignoring unknown variable '%s' in invitation.\n", l);
			continue;
		}

		if(!(variables[i].type & VAR_SAFE)) {
			fprintf(stderr, "Ignoring unsafe variable '%s' in invitation.\n", l);
			continue;
		}

		fprintf((variables[i].type & VAR_HOST) ? fh : f, "%s = %s\n", l, value);
	}

	fclose(f);

	/* Remaining chunks are other nodes' host files, copied verbatim. */
	while(more_chunks) {
		more_chunks = false;

		if(!check_id(value)) {
			join_error(j, "Invalid Name found in invitation");
			fclose(fh);
			return false;
		}

		if(!strcmp(value, j->name)) {
			join_error(j, "Secondary chunk would overwrite our own host config file");
			fclose(fh);
			return false;
		}

		FILE *fo = open_in_confbase(j, "host file", 0644, "hosts" SLASH "%s", value);

		if(!fo) {
			fclose(fh);
			return false;
		}

		while((l = get_line(&p, line, sizeof(line)))) {
			if(!strcmp(l, "#---------------------------------------------------------------#")) {
				continue;
			}

			size_t len = strcspn(l, "\t =");

			if(len == 4 && !strncasecmp(l, "Name", 4)) {
				value = split_variable(l);
				more_chunks = true;
				break;
			}

			fputs(l, fo);
			fputc('\n', fo);
		}

		fclose(fo);
	}

	/* Generate our key and send a copy to the server. */
	ecdsa_t *key = ecdsa_generate();

	if(!key) {
		join_error(j, "Could not generate Ed25519 key");
		fclose(fh);
		return false;
	}

	char *b64key = ecdsa_get_base64_public_key(key);
	FILE *fk = open_in_confbase(j, "private key", 0600, "ed25519_key.priv");

	if(!b64key || !fk || !ecdsa_write_pem_private_key(key, fk)) {
		join_error(j, "Error writing private key");

		if(fk) {
			fclose(fk);
		}

		fclose(fh);
		free(b64key);
		ecdsa_free(key);
		return false;
	}

	fclose(fk);
	fprintf(fh, "Ed25519PublicKey = %s\n", b64key);
	fclose(fh);

	bool sent = sptps_send_record(&j->sptps, 1, b64key, strlen(b64key));
	free(b64key);
	ecdsa_free(key);
	return sent;
}

/* ---------------------------------------------------------------------
   SPTPS callbacks
   --------------------------------------------------------------------- */

static bool invitation_send(void *handle, uint8_t type, const void *data, size_t len) {
	(void)type;
	join_t *j = handle;
	return send_all(j->sock, data, len);
}

static bool invitation_receive(void *handle, uint8_t type, const void *msg, uint16_t len) {
	join_t *j = handle;

	switch(type) {
	case SPTPS_HANDSHAKE:
		return sptps_send_record(&j->sptps, 0, j->cookie, sizeof(j->cookie));

	case 0:
		j->data = xrealloc(j->data, j->datalen + len + 1);
		memcpy(j->data + j->datalen, msg, len);
		j->datalen += len;
		j->data[j->datalen] = 0;
		break;

	case 1:
		return finalize_join(j);

	case 2:
		shutdown(j->sock, SHUT_RDWR);
		j->success = true;
		break;

	default:
		return false;
	}

	return true;
}

/* ---------------------------------------------------------------------
   Connecting
   --------------------------------------------------------------------- */

static int connect_with_timeout(const struct addrinfo *ai, int timeout_seconds) {
	int sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);

	if(sock < 0) {
		return -1;
	}

#ifdef SO_NOSIGPIPE
	int one = 1;
	setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif

	int flags = fcntl(sock, F_GETFL);
	fcntl(sock, F_SETFL, flags | O_NONBLOCK);

	if(connect(sock, ai->ai_addr, ai->ai_addrlen) && errno != EINPROGRESS) {
		close(sock);
		return -1;
	}

	struct pollfd pfd = {.fd = sock, .events = POLLOUT};
	int err = 0;
	socklen_t errlen = sizeof(err);

	if(poll(&pfd, 1, timeout_seconds * 1000) != 1 || getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &errlen) || err) {
		close(sock);
		errno = err ? err : ETIMEDOUT;
		return -1;
	}

	fcntl(sock, F_SETFL, flags);

	struct timeval tv = {.tv_sec = timeout_seconds, .tv_usec = 0};
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	return sock;
}

/* Parses host[:port]/<24 chars key hash><24 chars cookie>, as produced by `tinc invite`. */
static bool parse_url(join_t *j, char *url, char **address, char **port) {
	/* Be forgiving about what users paste. */
	while(isspace((unsigned char)*url)) {
		url++;
	}

	rstrip(url);

	char *slash = strrchr(url, '/');

	if(!slash || strlen(slash + 1) != 48) {
		return false;
	}

	*slash++ = 0;

	char *addr = url;
	char *prt = NULL;

	if(*addr == '[') {
		addr++;
		char *bracket = strchr(addr, ']');

		if(!bracket) {
			return false;
		}

		*bracket = 0;

		if(bracket[1] == ':') {
			prt = bracket + 2;
		}
	} else {
		prt = strchr(addr, ':');

		if(prt) {
			*prt++ = 0;
		}
	}

	if(!*addr) {
		return false;
	}

	*address = addr;
	*port = prt && *prt ? prt : "655";

	return b64decode(slash, j->hash, 24) == 18 && b64decode(slash + 24, j->cookie, 24) == 18;
}

char *tinc_ios_join(const char *confbase, const char *invitation_url, int timeout_seconds, char *error, size_t error_len) {
	tinc_ios_crypto_init();

	if(error && error_len) {
		*error = 0;
	}

	if(timeout_seconds <= 0) {
		timeout_seconds = 15;
	}

	join_t *j = xzalloc(sizeof(*j));
	j->confbase = confbase;
	j->sock = -1;
	j->error = error;
	j->error_len = error_len;

	char *result = NULL;
	char *url = xstrdup(invitation_url);
	char *address, *port;
	ecdsa_t *key = NULL;
	ecdsa_t *hiskey = NULL;
	char *b64key = NULL;
	struct addrinfo *ai = NULL;
	bool sptps_started = false;

	if(!parse_url(j, url, &address, &port)) {
		join_error(j, "Invalid invitation URL");
		goto done;
	}

	/* A throw-away key for the invitation handshake. */
	key = ecdsa_generate();
	b64key = key ? ecdsa_get_base64_public_key(key) : NULL;

	if(!b64key) {
		join_error(j, "Could not generate a key");
		goto done;
	}

	ai = str2addrinfo(address, port, SOCK_STREAM);

	if(!ai) {
		join_error(j, "Could not resolve %s port %s", address, port);
		goto done;
	}

	char line[4096];
	int code, hismajor, hisminor = 0;
	char hisname[4096] = "";

	for(struct addrinfo *aip = ai; aip; aip = aip->ai_next) {
		j->sock = connect_with_timeout(aip, timeout_seconds);

		if(j->sock < 0) {
			join_error(j, "Could not connect to %s port %s: %s", address, port, strerror(errno));
			continue;
		}

		/* Tell him we have an invitation, and give him our throw-away key. */
		int len = snprintf(line, sizeof(line), "%d ?%s %d.%d\n", ID, b64key, PROT_MAJOR, 1);

		if(len > 0 && (size_t)len < sizeof(line) && send_all(j->sock, line, len)
		                && recvline(j, line, sizeof(line))
		                && sscanf(line, "%d %4095s %d.%d", &code, hisname, &hismajor, &hisminor) >= 3
		                && code == 0 && hismajor == PROT_MAJOR && check_id(hisname)
		                && recvline(j, line, sizeof(line)) && rstrip(line)
		                && sscanf(line, "%d ", &code) == 1 && code == ACK && strlen(line) >= 3) {
			break;
		}

		join_error(j, "Cannot read greeting from %s port %s", address, port);
		close(j->sock);
		j->sock = -1;
		j->blen = 0;
	}

	if(j->sock < 0) {
		goto done;
	}

	/* Check that the hash of the key he gave us matches the hash in the URL. */
	char *fingerprint = line + 2;
	char hishash[64];

	if(sha512(fingerprint, strlen(fingerprint), hishash) || memcmp(hishash, j->hash, 18)) {
		join_error(j, "Peer has an invalid key; the invitation may be for a different node");
		goto done;
	}

	hiskey = ecdsa_set_base64_public_key(fingerprint);

	if(!hiskey) {
		join_error(j, "Peer sent an invalid key");
		goto done;
	}

	if(!sptps_start(&j->sptps, j, true, false, key, hiskey, "tinc invitation", 15, invitation_send, invitation_receive)) {
		join_error(j, "Could not start SPTPS session");
		goto done;
	}

	sptps_started = true;

	/* Feed whatever arrived after the greeting to SPTPS, then the rest of the stream. */
	if(j->blen && sptps_receive_data(&j->sptps, j->buffer, j->blen) != j->blen) {
		join_error(j, "Invitation protocol error");
		goto done;
	}

	for(;;) {
		ssize_t len = recv(j->sock, line, sizeof(line), 0);

		if(len < 0 && errno == EINTR) {
			continue;
		}

		if(len < 0) {
			if(!j->success) {
				join_error(j, "Error reading from %s port %s: %s", address, port, strerror(errno));
			}

			break;
		}

		if(len == 0) {
			break;
		}

		char *p = line;

		while(len) {
			size_t done = sptps_receive_data(&j->sptps, p, len);

			if(!done) {
				join_error(j, "Invitation was rejected or the protocol failed");
				goto done;
			}

			len -= done;
			p += done;
		}
	}

	if(!j->success) {
		join_error(j, "Connection closed by peer, invitation cancelled");
		goto done;
	}

	char *name_q = tinc_ios_json_quote(j->name);
	char *netname_q = tinc_ios_json_quote(j->netname);
	xasprintf(&result, "{\"name\":%s,\"netname\":%s,\"ifconfig\":[%s],\"routes\":[%s]}",
	          name_q, netname_q, j->ifconfig_json ? j->ifconfig_json : "", j->routes_json ? j->routes_json : "");
	free(name_q);
	free(netname_q);

done:

	if(sptps_started) {
		sptps_stop(&j->sptps);
	}

	if(j->sock >= 0) {
		close(j->sock);
	}

	if(ai) {
		freeaddrinfo(ai);
	}

	ecdsa_free(hiskey);
	ecdsa_free(key);
	free(b64key);
	free(url);
	free(j->data);
	free(j->ifconfig_json);
	free(j->routes_json);
	free(j);
	return result;
}
