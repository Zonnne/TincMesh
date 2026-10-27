/*
    node_harness.c -- run one tinc node through the TincCore iOS API

    Plays the role of PacketTunnelProvider: it creates the packet
    socketpair, runs tinc_ios_run() on a thread, and acts as a tiny IP
    stack on the other end. It answers ICMP echo requests addressed to
    its own VPN address and, if a peer address is given, pings the peer
    through the tinc mesh.

    Usage:
      node_harness responder <confbase> <logfile> <my-ip>
          Answer pings until SIGTERM/SIGINT.
      node_harness exit <confbase> <logfile> <my-ip> <name>
          Act as an exit node's "internet": answer DNS queries to any
          address (every A record is 198.51.100.7), echo UDP datagrams to
          any address back prefixed with "<name>:", and answer pings.
      node_harness ping <confbase> <logfile> <my-ip> <peer-ip> [--restart]
          Ping peer (small and large packets), exercise status/retry/
          reload, stop; with --restart run tinc a second time in the same
          process and ping again. Exits 0 on success.
*/

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "tinc_ios.h"

static const char *confbase;
static const char *logfile;
static uint32_t my_ip;
static uint32_t peer_ip;
static int app_fd = -1;
static volatile sig_atomic_t terminate = 0;
static const char *exit_name = NULL;

static pthread_mutex_t ready_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t ready_cond = PTHREAD_COND_INITIALIZER;
static bool ready = false;
static int run_result = -1;
static bool run_finished = false;

static double now_seconds(void) {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec + tv.tv_usec / 1e6;
}

static uint16_t checksum(const void *data, size_t len) {
	const uint8_t *p = data;
	uint32_t sum = 0;

	for(size_t i = 0; i + 1 < len; i += 2) {
		sum += (p[i] << 8) | p[i + 1];
	}

	if(len & 1) {
		sum += p[len - 1] << 8;
	}

	while(sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	return htons(~sum & 0xffff);
}

/* Builds an IPv4 ICMP echo request of total length len. */
static size_t make_ping(uint8_t *buf, size_t len, uint32_t src, uint32_t dst, uint16_t seq) {
	memset(buf, 0, len);
	buf[0] = 0x45;
	buf[2] = len >> 8;
	buf[3] = len & 0xff;
	buf[4] = 0x12;
	buf[5] = 0x34;
	buf[8] = 64;   /* TTL */
	buf[9] = 1;    /* ICMP */
	memcpy(buf + 12, &src, 4);
	memcpy(buf + 16, &dst, 4);
	uint16_t sum = checksum(buf, 20);
	memcpy(buf + 10, &sum, 2);

	uint8_t *icmp = buf + 20;
	icmp[0] = 8;   /* echo request */
	icmp[4] = 0xbe;
	icmp[5] = 0xef;
	icmp[6] = seq >> 8;
	icmp[7] = seq & 0xff;

	for(size_t i = 8; i < len - 20; i++) {
		icmp[i] = (uint8_t)i;
	}

	sum = checksum(icmp, len - 20);
	memcpy(icmp + 2, &sum, 2);
	return len;
}

/* Sends a UDP datagram from src:sport to dst:dport. */
static void send_udp(const uint8_t *src, uint16_t sport, const uint8_t *dst, uint16_t dport, const uint8_t *payload, size_t plen) {
	uint8_t pkt[2048];
	size_t len = 28 + plen;

	if(len > sizeof(pkt)) {
		return;
	}

	memset(pkt, 0, 28);
	pkt[0] = 0x45;
	pkt[2] = len >> 8;
	pkt[3] = len & 0xff;
	pkt[8] = 64;
	pkt[9] = 17;
	memcpy(pkt + 12, src, 4);
	memcpy(pkt + 16, dst, 4);
	uint16_t sum = checksum(pkt, 20);
	memcpy(pkt + 10, &sum, 2);
	pkt[20] = sport >> 8;
	pkt[21] = sport & 0xff;
	pkt[22] = dport >> 8;
	pkt[23] = dport & 0xff;
	pkt[24] = (8 + plen) >> 8;
	pkt[25] = (8 + plen) & 0xff;
	memcpy(pkt + 28, payload, plen);   /* UDP checksum 0: none */
	send(app_fd, pkt, len, 0);
}

/* Exit node behaviour: answer for any destination address. */
static void handle_exit_packet(const uint8_t *buf, ssize_t len) {
	if(len < 28 || (buf[0] >> 4) != 4 || buf[9] != 17) {
		return;
	}

	size_t ihl = (buf[0] & 0xf) * 4;
	const uint8_t *udp = buf + ihl;
	uint16_t sport = udp[0] << 8 | udp[1];
	uint16_t dport = udp[2] << 8 | udp[3];
	size_t plen = (size_t)len - ihl - 8;
	const uint8_t *payload = udp + 8;
	uint8_t reply[1500];

	if(dport == 53 && plen >= 17) {
		/* DNS: echo the question, and for A queries add 198.51.100.7. */
		size_t qend = 12;

		while(qend < plen && payload[qend]) {
			qend += payload[qend] + 1;
		}

		qend += 5;

		if(qend > plen || qend + 16 > sizeof(reply)) {
			return;
		}

		uint16_t qtype = payload[qend - 4] << 8 | payload[qend - 3];
		memcpy(reply, payload, qend);
		reply[2] = 0x81;
		reply[3] = 0x80;
		reply[6] = 0;
		reply[7] = qtype == 1;
		memset(reply + 8, 0, 4);
		size_t rlen = qend;

		if(qtype == 1) {
			const uint8_t rr[16] = {0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4, 198, 51, 100, 7};
			memcpy(reply + qend, rr, sizeof(rr));
			rlen += sizeof(rr);
		}

		send_udp(buf + 16, dport, buf + 12, sport, reply, rlen);
		return;
	}

	size_t nlen = strlen(exit_name);

	if(nlen + 1 + plen > sizeof(reply)) {
		return;
	}

	memcpy(reply, exit_name, nlen);
	reply[nlen] = ':';
	memcpy(reply + nlen + 1, payload, plen);
	send_udp(buf + 16, dport, buf + 12, sport, reply, nlen + 1 + plen);
}

/* Handles one packet from tinc. Returns the echo reply sequence number
   (>= 0) if this was a valid reply from the peer, -1 otherwise. */
static int handle_packet(uint8_t *buf, ssize_t len) {
	if(exit_name) {
		handle_exit_packet(buf, len);
	}

	if(len < 28 || (buf[0] >> 4) != 4 || buf[9] != 1) {
		return -1;
	}

	size_t ihl = (buf[0] & 0xf) * 4;
	uint8_t *icmp = buf + ihl;
	size_t icmplen = len - ihl;
	uint32_t src, dst;
	memcpy(&src, buf + 12, 4);
	memcpy(&dst, buf + 16, 4);

	if(dst != my_ip || checksum(icmp, icmplen) != 0) {
		return -1;
	}

	if(icmp[0] == 8) {
		/* Echo request: turn it around. Swapping addresses keeps the IP checksum valid. */
		memcpy(buf + 12, &dst, 4);
		memcpy(buf + 16, &src, 4);
		icmp[0] = 0;
		icmp[2] = icmp[3] = 0;
		uint16_t sum = checksum(icmp, icmplen);
		memcpy(icmp + 2, &sum, 2);
		send(app_fd, buf, len, 0);
		return -1;
	}

	if(icmp[0] == 0 && src == peer_ip && icmp[4] == 0xbe && icmp[5] == 0xef) {
		return (icmp[6] << 8) | icmp[7];
	}

	return -1;
}

static void on_ready(void *context) {
	(void)context;
	pthread_mutex_lock(&ready_lock);
	ready = true;
	pthread_cond_broadcast(&ready_cond);
	pthread_mutex_unlock(&ready_lock);
}

static void *tinc_thread(void *arg) {
	int tun_fd = (int)(intptr_t)arg;
	tinc_ios_options options = {
		.confbase = confbase,
		.logfile = logfile,
		.tun_fd = tun_fd,
		.debug_level = 3,
		.ready = on_ready,
	};
	int result = tinc_ios_run(&options);
	pthread_mutex_lock(&ready_lock);
	run_result = result;
	run_finished = true;
	pthread_cond_broadcast(&ready_cond);
	pthread_mutex_unlock(&ready_lock);
	return NULL;
}

static bool start_tinc(pthread_t *thread) {
	int sv[2];

	if(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv)) {
		perror("socketpair");
		return false;
	}

	app_fd = sv[0];
	ready = false;
	run_finished = false;

	if(pthread_create(thread, NULL, tinc_thread, (void *)(intptr_t)sv[1])) {
		return false;
	}

	pthread_mutex_lock(&ready_lock);

	while(!ready && !run_finished) {
		pthread_cond_wait(&ready_cond, &ready_lock);
	}

	bool ok = ready;
	pthread_mutex_unlock(&ready_lock);

	if(!ok) {
		fprintf(stderr, "tinc_ios_run failed during setup (result %d)\n", run_result);
	}

	return ok;
}

static bool stop_tinc(pthread_t thread) {
	tinc_ios_stop();
	pthread_join(thread, NULL);
	close(app_fd);
	app_fd = -1;

	if(run_result != 0) {
		fprintf(stderr, "tinc_ios_run returned %d\n", run_result);
		return false;
	}

	/* Status must report "not running" once stopped. */
	char *status = tinc_ios_status_json();

	if(status) {
		fprintf(stderr, "status still available after stop\n");
		free(status);
		return false;
	}

	return true;
}

/* Pings the peer with packets of the given size until a reply arrives. */
static bool ping_peer(size_t size, double timeout) {
	uint8_t buf[2048];
	static uint16_t seq = 0;
	double deadline = now_seconds() + timeout;
	double next_send = 0;
	double started = now_seconds();

	while(now_seconds() < deadline) {
		if(now_seconds() >= next_send) {
			seq++;
			size_t len = make_ping(buf, size, my_ip, peer_ip, seq);

			if(send(app_fd, buf, len, 0) < 0) {
				perror("send");
			}

			next_send = now_seconds() + 0.5;
		}

		struct pollfd pfd = {.fd = app_fd, .events = POLLIN};

		if(poll(&pfd, 1, 100) == 1) {
			ssize_t len = recv(app_fd, buf, sizeof(buf), 0);

			if(len > 0 && handle_packet(buf, len) >= 0) {
				printf("  reply to %zu-byte ping after %.2fs\n", size, now_seconds() - started);
				return true;
			}
		}
	}

	fprintf(stderr, "no reply to %zu-byte ping within %.0fs\n", size, timeout);
	return false;
}

static bool check_status(const char *peer_name) {
	char *status = tinc_ios_status_json();

	if(!status) {
		fprintf(stderr, "tinc_ios_status_json() returned NULL\n");
		return false;
	}

	char path[4096];
	snprintf(path, sizeof(path), "%s/status.json", confbase);
	FILE *f = fopen(path, "w");

	if(f) {
		fputs(status, f);
		fclose(f);
	}

	char needle[256];
	snprintf(needle, sizeof(needle), "\"name\":\"%s\",\"myself\":false,\"reachable\":true", peer_name);
	bool ok = strstr(status, needle) != NULL;

	if(!ok) {
		fprintf(stderr, "status does not show %s as reachable:\n%s\n", peer_name, status);
	}

	free(status);
	return ok;
}

static void on_signal(int sig) {
	(void)sig;
	terminate = 1;
}

static int responder(void) {
	pthread_t thread;
	signal(SIGTERM, on_signal);
	signal(SIGINT, on_signal);

	if(!start_tinc(&thread)) {
		return 1;
	}

	printf("responder ready\n");
	fflush(stdout);

	uint8_t buf[2048];

	while(!terminate && !run_finished) {
		struct pollfd pfd = {.fd = app_fd, .events = POLLIN};

		if(poll(&pfd, 1, 200) == 1) {
			ssize_t len = recv(app_fd, buf, sizeof(buf), 0);

			if(len > 0) {
				handle_packet(buf, len);
			}
		}
	}

	return stop_tinc(thread) ? 0 : 1;
}

static int pinger(const char *peer_name, bool restart) {
	int rounds = restart ? 2 : 1;

	for(int round = 1; round <= rounds; round++) {
		pthread_t thread;
		printf("round %d: starting tinc %s\n", round, tinc_ios_version());

		if(!start_tinc(&thread)) {
			return 1;
		}

		if(!ping_peer(64, 30) || !ping_peer(1400, 30) || !check_status(peer_name)) {
			stop_tinc(thread);
			return 1;
		}

		/* Exercise the control paths the extension uses on network changes. */
		tinc_ios_retry();
		tinc_ios_reload();

		if(!ping_peer(64, 30) || !check_status(peer_name)) {
			stop_tinc(thread);
			return 1;
		}

		if(!stop_tinc(thread)) {
			return 1;
		}

		printf("round %d: ok\n", round);
	}

	return 0;
}

int main(int argc, char *argv[]) {
	if(argc < 5) {
		fprintf(stderr, "usage: %s responder|ping <confbase> <logfile> <my-ip> [<peer-ip> <peer-name> [--restart]]\n", argv[0]);
		return 2;
	}

	confbase = argv[2];
	logfile = strcmp(argv[3], "-") ? argv[3] : NULL;

	if(inet_pton(AF_INET, argv[4], &my_ip) != 1) {
		fprintf(stderr, "bad address %s\n", argv[4]);
		return 2;
	}

	setvbuf(stdout, NULL, _IOLBF, 0);

	if(!strcmp(argv[1], "responder")) {
		return responder();
	}

	if(!strcmp(argv[1], "exit") && argc >= 6) {
		exit_name = argv[5];
		return responder();
	}

	if(!strcmp(argv[1], "ping") && argc >= 7 && inet_pton(AF_INET, argv[5], &peer_ip) == 1) {
		return pinger(argv[6], argc > 7 && !strcmp(argv[7], "--restart"));
	}

	fprintf(stderr, "bad arguments\n");
	return 2;
}
