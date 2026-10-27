/*
    policy_harness.c -- end-to-end test of rule-based routing (policy.c)

    Runs a tinc node with rules, playing the apps' side of the packet
    tunnel: it sends DNS queries to the in-tunnel resolver and UDP probes
    to the returned addresses, and checks which exit node answered. Both
    exit nodes (see node_harness exit) resolve every name to the same
    address, 198.51.100.7, so the test also proves that routing is per
    connection rather than per destination address.

    Usage: policy_harness <confbase> <logfile> <my-ip> <direct-dns-port>
*/

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "tinc_ios.h"

static int app_fd = -1;
static uint8_t my_ip[4];
static int failures = 0;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static bool ready = false, finished = false;

#define CHECK(cond, ...) do { \
		if(!(cond)) { printf("  FAILED: "); printf(__VA_ARGS__); printf("\n"); failures++; } \
		else { printf("  ok: "); printf(__VA_ARGS__); printf("\n"); } \
	} while(0)

static double now_seconds(void) {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec + tv.tv_usec / 1e6;
}

static uint16_t checksum(const uint8_t *p, size_t len) {
	uint32_t sum = 0;

	for(size_t i = 0; i + 1 < len; i += 2) {
		sum += p[i] << 8 | p[i + 1];
	}

	while(sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	uint16_t r = ~sum;
	return htons(r);
}

static void send_udp(const uint8_t *dst, uint16_t sport, uint16_t dport, const uint8_t *payload, size_t plen) {
	uint8_t pkt[1600] = {0};
	size_t len = 28 + plen;
	pkt[0] = 0x45;
	pkt[2] = len >> 8;
	pkt[3] = len & 0xff;
	pkt[8] = 64;
	pkt[9] = 17;
	memcpy(pkt + 12, my_ip, 4);
	memcpy(pkt + 16, dst, 4);
	uint16_t sum = checksum(pkt, 20);
	memcpy(pkt + 10, &sum, 2);
	pkt[20] = sport >> 8;
	pkt[21] = sport & 0xff;
	pkt[22] = dport >> 8;
	pkt[23] = dport & 0xff;
	pkt[24] = (8 + plen) >> 8;
	pkt[25] = (8 + plen) & 0xff;
	memcpy(pkt + 28, payload, plen);
	send(app_fd, pkt, len, 0);
}

/* Waits for a UDP datagram to sport. Returns payload length, or -1. */
static int recv_udp(uint16_t sport, uint8_t *src, uint16_t *from_port, uint8_t *payload, size_t size, double timeout) {
	double deadline = now_seconds() + timeout;
	uint8_t pkt[2048];

	while(now_seconds() < deadline) {
		struct pollfd pfd = {.fd = app_fd, .events = POLLIN};

		if(poll(&pfd, 1, 100) != 1) {
			continue;
		}

		ssize_t len = recv(app_fd, pkt, sizeof(pkt), 0);

		if(len < 28 || (pkt[0] >> 4) != 4 || pkt[9] != 17) {
			continue;
		}

		size_t ihl = (pkt[0] & 0xf) * 4;
		uint8_t *udp = pkt + ihl;

		if((udp[2] << 8 | udp[3]) != sport || memcmp(pkt + 16, my_ip, 4)) {
			continue;
		}

		/* Verify the IP header checksum the engine computed or patched. */
		if(checksum(pkt, ihl) != 0) {
			printf("  bad IP checksum on reply\n");
			failures++;
		}

		memcpy(src, pkt + 12, 4);
		*from_port = udp[0] << 8 | udp[1];
		size_t plen = len - ihl - 8;

		if(plen > size) {
			plen = size;
		}

		memcpy(payload, udp + 8, plen);
		return (int)plen;
	}

	return -1;
}

typedef struct dns_result_t {
	int rcode;      /* -1: no answer */
	int answers;
	uint8_t a[4];
	bool has_a;
} dns_result_t;

static dns_result_t dns_query(const char *name, uint16_t qtype) {
	static uint16_t next_port = 33000;
	uint8_t q[512] = {0};
	uint16_t id = rand() & 0xffff;
	q[0] = id >> 8;
	q[1] = id & 0xff;
	q[2] = 0x01;   /* RD */
	q[5] = 1;
	size_t off = 12;
	char copy[256];
	snprintf(copy, sizeof(copy), "%s", name);

	for(char *label = strtok(copy, "."); label; label = strtok(NULL, ".")) {
		size_t l = strlen(label);
		q[off++] = l;
		memcpy(q + off, label, l);
		off += l;
	}

	q[off++] = 0;
	q[off++] = qtype >> 8;
	q[off++] = qtype & 0xff;
	q[off++] = 0;
	q[off++] = 1;

	uint16_t port = next_port++;
	const uint8_t dns_ip[4] = {198, 18, 0, 2};
	dns_result_t r = {.rcode = -1};
	uint8_t src[4], resp[1500];
	uint16_t from;

	for(int attempt = 0; attempt < 3 && r.rcode < 0; attempt++) {
		send_udp(dns_ip, port, 53, q, off);
		int len = recv_udp(port, src, &from, resp, sizeof(resp), 3);

		if(len < 12 || resp[0] != q[0] || resp[1] != q[1] || memcmp(src, dns_ip, 4) || from != 53) {
			continue;
		}

		r.rcode = resp[3] & 0xf;
		r.answers = resp[6] << 8 | resp[7];
		size_t p = off;

		for(int i = 0; i < r.answers && p + 12 <= (size_t)len; i++) {
			p += (resp[p] & 0xc0) == 0xc0 ? 2 : 0;
			uint16_t type = resp[p] << 8 | resp[p + 1];
			uint16_t rdlen = resp[p + 8] << 8 | resp[p + 9];

			if(type == 1 && rdlen == 4 && !r.has_a) {
				memcpy(r.a, resp + p + 10, 4);
				r.has_a = true;
			}

			p += 10 + rdlen;
		}
	}

	return r;
}

/* Sends a probe to addr:9999 and returns which exit node answered ("x", "y", or ""). */
static const char *probe(const uint8_t *addr, const char *label) {
	static char answer[64];
	static uint16_t next_port = 41000;
	uint16_t port = next_port++;
	uint8_t src[4], payload[256];
	uint16_t from;
	answer[0] = 0;

	for(int attempt = 0; attempt < 5 && !answer[0]; attempt++) {
		send_udp(addr, port, 9999, (const uint8_t *)label, strlen(label));
		int len = recv_udp(port, src, &from, payload, sizeof(payload) - 1, 2);

		if(len <= 0) {
			continue;
		}

		payload[len] = 0;

		/* The reply must come from the address the app talked to (fake addresses translated back). */
		if(memcmp(src, addr, 4) || from != 9999) {
			printf("  reply came from %d.%d.%d.%d:%d instead of %d.%d.%d.%d:9999\n", src[0], src[1], src[2], src[3], from,
			       addr[0], addr[1], addr[2], addr[3]);
			failures++;
		}

		char *colon = strchr((char *)payload, ':');

		if(colon && !strcmp(colon + 1, label)) {
			*colon = 0;
			snprintf(answer, sizeof(answer), "%s", (char *)payload);
		}
	}

	return answer;
}

static bool is_fake(const uint8_t *a) {
	return a[0] == 198 && (a[1] == 18 || a[1] == 19);
}

/* A tiny DNS server standing in for the device's normal resolver. */
static void *direct_dns_thread(void *arg) {
	int port = (int)(intptr_t)arg;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in sin = {.sin_family = AF_INET, .sin_port = htons(port)};
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if(bind(fd, (struct sockaddr *)&sin, sizeof(sin))) {
		perror("bind direct dns");
		return NULL;
	}

	for(;;) {
		uint8_t q[512], r[600];
		struct sockaddr_in from;
		socklen_t fromlen = sizeof(from);
		ssize_t len = recvfrom(fd, q, sizeof(q), 0, (struct sockaddr *)&from, &fromlen);

		if(len < 17) {
			continue;
		}

		memcpy(r, q, len);
		r[2] = 0x81;
		r[3] = 0x80;
		r[7] = 1;
		r[11] = 0;
		r[9] = 0;
		const uint8_t rr[16] = {0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 99};
		memcpy(r + len, rr, sizeof(rr));
		sendto(fd, r, len + sizeof(rr), 0, (struct sockaddr *)&from, fromlen);
	}

	return NULL;
}

static void on_ready(void *ctx) {
	(void)ctx;
	pthread_mutex_lock(&lock);
	ready = true;
	pthread_cond_broadcast(&cond);
	pthread_mutex_unlock(&lock);
}

static const char *confbase, *logfile;

static void *tinc_thread(void *arg) {
	tinc_ios_options options = {
		.confbase = confbase, .logfile = logfile, .tun_fd = (int)(intptr_t)arg, .debug_level = 5, .ready = on_ready,
	};
	tinc_ios_run(&options);
	pthread_mutex_lock(&lock);
	finished = true;
	pthread_cond_broadcast(&cond);
	pthread_mutex_unlock(&lock);
	return NULL;
}

static bool wait_for_nodes(void) {
	double deadline = now_seconds() + 30;

	while(now_seconds() < deadline) {
		char *s = tinc_ios_status_json();
		bool ok = s && strstr(s, "\"name\":\"x\",\"myself\":false,\"reachable\":true")
		          && strstr(s, "\"name\":\"y\",\"myself\":false,\"reachable\":true");
		free(s);

		if(ok) {
			return true;
		}

		usleep(200000);
	}

	return false;
}

static const char *RULES =
        "# TincMesh test rules\n"
        "[General]\n"
        "dns-server = 192.0.2.53\n"
        "direct-dns-server = 127.0.0.1:%d\n"
        "\n"
        "[Proxy Group]\n"
        "backup = fallback, missing_node, y\n"
        "auto = url-test, x, y\n"
        "\n"
        "[Rule]\n"
        "DOMAIN-SUFFIX,a.test,x\n"
        "DOMAIN,b.test,y\n"
        "DOMAIN-KEYWORD,backupkw,backup\n"
        "DOMAIN-SUFFIX,fast.test,auto\n"
        "DOMAIN-SUFFIX,blocked.test,REJECT\n"
        "IP-CIDR,203.0.113.0/24,y\n"
        "GEOIP,CN,DIRECT\n"
        "FINAL,DIRECT\n";

int main(int argc, char *argv[]) {
	if(argc != 5) {
		fprintf(stderr, "usage: %s <confbase> <logfile> <my-ip> <direct-dns-port>\n", argv[0]);
		return 2;
	}

	setvbuf(stdout, NULL, _IOLBF, 0);
	confbase = argv[1];
	logfile = argv[2];
	inet_pton(AF_INET, argv[3], my_ip);
	int dns_port = atoi(argv[4]);
	srand(getpid());

	pthread_t dns;
	pthread_create(&dns, NULL, direct_dns_thread, (void *)(intptr_t)dns_port);

	char rules[2048];
	snprintf(rules, sizeof(rules), RULES, dns_port);
	char error[256];

	printf("rules validation\n");
	char *summary = tinc_ios_policy_check(rules, error, sizeof(error));
	CHECK(summary != NULL, "rules parse (%s)", summary ? "" : error);

	if(summary) {
		printf("  summary: %s\n", summary);
		CHECK(strstr(summary, "\"capture_all_dns\":true") != NULL, "keyword rule captures all DNS");
		CHECK(strstr(summary, "\"match_domains\":[\"a.test\",\"b.test\"") != NULL, "domain rules listed for split DNS");
		CHECK(strstr(summary, "\"include_routes\":[\"203.0.113.0/24\"]") != NULL, "IP-CIDR rule routed into the tunnel");
		CHECK(strstr(summary, "GEOIP rules are not supported") != NULL, "unsupported rule reported as a warning");
		free(summary);
	}

	CHECK(!tinc_ios_policy_check("[Rule]\nDOMAIN,x.test,no-such-node!\n", error, sizeof(error)) && strstr(error, "Line 2"),
	      "invalid policy rejected with line number (%s)", error);
	CHECK(!tinc_ios_policy_check("[Proxy Group]\ng = round-robin, x\n", error, sizeof(error)), "unknown group type rejected (%s)", error);
	CHECK(tinc_ios_set_policy(rules, error, sizeof(error)), "rules installed before start");

	int sv[2];
	socketpair(AF_UNIX, SOCK_DGRAM, 0, sv);
	app_fd = sv[0];
	pthread_t thread;
	pthread_create(&thread, NULL, tinc_thread, (void *)(intptr_t)sv[1]);
	pthread_mutex_lock(&lock);

	while(!ready && !finished) {
		pthread_cond_wait(&cond, &lock);
	}

	pthread_mutex_unlock(&lock);

	if(!ready || !wait_for_nodes()) {
		printf("  FAILED: exit nodes x and y did not become reachable\n");
		tinc_ios_stop();
		return 1;
	}

	/* Like real traffic, the first packets to a node only start tinc's key exchange. */
	printf("warming up paths to the exit nodes\n");
	const uint8_t x_ip[4] = {10, 99, 0, 11}, y_ip[4] = {10, 99, 0, 12};
	double warm_deadline = now_seconds() + 30;
	bool x_ok = false, y_ok = false;

	while((!x_ok || !y_ok) && now_seconds() < warm_deadline) {
		x_ok = x_ok || !strcmp(probe(x_ip, "warmup"), "x");
		y_ok = y_ok || !strcmp(probe(y_ip, "warmup"), "y");
	}

	CHECK(x_ok && y_ok, "x and y answer through the mesh");

	printf("domain rules\n");
	dns_result_t a = dns_query("a.test", 1);
	CHECK(a.rcode == 0 && a.has_a && is_fake(a.a), "a.test resolves to fake %d.%d.%d.%d", a.a[0], a.a[1], a.a[2], a.a[3]);
	CHECK(!strcmp(probe(a.a, "hello-a"), "x"), "a.test is carried by x");

	dns_result_t b = dns_query("b.test", 1);
	CHECK(b.rcode == 0 && b.has_a && is_fake(b.a) && memcmp(a.a, b.a, 4), "b.test gets a different fake address");
	CHECK(!strcmp(probe(b.a, "hello-b"), "y"), "b.test is carried by y, though both resolve to 198.51.100.7");
	CHECK(!strcmp(probe(a.a, "again-a"), "x"), "a.test still pinned to x");

	dns_result_t a2 = dns_query("a.test", 1);
	CHECK(a2.has_a && !memcmp(a2.a, a.a, 4), "repeated query returns the same fake address");

	dns_result_t www = dns_query("www.a.test", 1);
	CHECK(www.has_a && is_fake(www.a) && !strcmp(probe(www.a, "hello-www"), "x"), "DOMAIN-SUFFIX matches subdomains");

	dns_result_t sub = dns_query("sub.b.test", 1);
	CHECK(sub.has_a && !is_fake(sub.a) && sub.a[3] == 99, "DOMAIN does not match subdomains (direct answer)");

	dns_result_t kw = dns_query("my-backupkw.example", 1);
	CHECK(kw.has_a && is_fake(kw.a) && !strcmp(probe(kw.a, "hello-kw"), "y"), "fallback group skips the missing node and uses y");

	dns_result_t fast = dns_query("fast.test", 1);
	const char *fast_node = fast.has_a ? probe(fast.a, "hello-fast") : "";
	CHECK(!strcmp(fast_node, "x") || !strcmp(fast_node, "y"), "url-test group picks a reachable node (%s)", fast_node);

	dns_result_t blocked = dns_query("ads.blocked.test", 1);
	CHECK(blocked.rcode == 3, "REJECT answers NXDOMAIN");

	dns_result_t plain = dns_query("plain.example", 1);
	CHECK(plain.rcode == 0 && plain.has_a && plain.a[0] == 192 && plain.a[3] == 99, "unmatched names use the direct resolver");

	dns_result_t aaaa = dns_query("a.test", 28);
	CHECK(aaaa.rcode == 0 && aaaa.answers == 0, "AAAA for routed names is empty");

	printf("IP rules\n");
	const uint8_t cidr_addr[4] = {203, 0, 113, 9};
	CHECK(!strcmp(probe(cidr_addr, "hello-cidr"), "y"), "IP-CIDR 203.0.113.0/24 is carried by y");

	char *status = tinc_ios_status_json();
	CHECK(status && strstr(status, "\"policy\":{\"enabled\":true") && strstr(status, "{\"name\":\"backup\",\"selected\":\"y\"}"),
	      "status reports the policy and group selection");

	if(status) {
		char *p = strstr(status, "\"policy\":");
		printf("  %s\n", p ? p : status);
		free(status);
	}

	printf("live rule change\n");
	char changed[2048];
	snprintf(changed, sizeof(changed), "[General]\ndns-server = 192.0.2.53\ndirect-dns-server = 127.0.0.1:%d\n[Rule]\nDOMAIN-SUFFIX,a.test,y\n", dns_port);
	CHECK(tinc_ios_set_policy(changed, error, sizeof(error)), "new rules accepted while running");
	usleep(300000);
	dns_result_t a3 = dns_query("a.test", 1);
	CHECK(a3.has_a && is_fake(a3.a) && !strcmp(probe(a3.a, "moved-a"), "y"), "a.test now carried by y");

	CHECK(tinc_ios_set_policy(NULL, error, sizeof(error)), "rules disabled");
	usleep(300000);
	status = tinc_ios_status_json();
	CHECK(status && strstr(status, "\"policy\":{\"enabled\":false}"), "status shows rules disabled");
	free(status);

	tinc_ios_stop();
	pthread_join(thread, NULL);

	if(failures) {
		printf("%d check(s) failed\n", failures);
		return 1;
	}

	printf("policy ok\n");
	return 0;
}
