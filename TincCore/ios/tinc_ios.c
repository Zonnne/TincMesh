/*
    tinc_ios.c -- run tincd as a library inside the iOS packet tunnel extension

    This replaces tincd.c's main(). It performs the same startup sequence
    (read configuration, set up the network, run the event loop, tear down)
    but on the caller's thread, with an extra control pipe that lets other
    threads stop, retry, reload, or snapshot the daemon safely: all real
    work happens on the tinc thread, because tinc's state is not
    thread-safe.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "../tinc/system.h"

#include <pthread.h>

#include "../tinc/conf.h"
#include "../tinc/connection.h"
#include "../tinc/crypto.h"
#include "../tinc/edge.h"
#include "../tinc/event.h"
#include "../tinc/logger.h"
#include "../tinc/names.h"
#include "../tinc/net.h"
#include "../tinc/netutl.h"
#include "../tinc/node.h"
#include "../tinc/process.h"
#include "../tinc/protocol.h"
#include "../tinc/subnet.h"
#include "../tinc/utils.h"
#include "../tinc/version.h"
#include "../tinc/xalloc.h"

#include "tinc_ios.h"
#include "tinc_ios_private.h"

/* Normally defined in tincd.c. */
bool bypass_security = false;

int tinc_ios_tun_fd = -1;

#define LOG_ROTATE_SIZE (1024 * 1024)
#define LOG_ROTATE_INTERVAL 30
#define STATUS_TIMEOUT_SECONDS 3

static pthread_mutex_t state_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t state_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t status_request_lock = PTHREAD_MUTEX_INITIALIZER;

/* Protected by state_lock. */
static bool in_run = false;
static bool running = false;
static bool stop_requested = false;
static int ctl_write_fd = -1;
static char *status_result = NULL;
static bool status_done = false;

/* Only touched by the tinc thread. */
static int ctl_read_fd = -1;
static io_t ctl_io;
static timeout_t log_timer;

const char *tinc_ios_version(void) {
	return BUILD_VERSION;
}

/* ---------------------------------------------------------------------
   JSON snapshot
   --------------------------------------------------------------------- */

typedef struct json_t {
	char *buf;
	size_t len;
	size_t size;
} json_t;

static void json_append(json_t *j, const char *s, size_t n) {
	if(j->len + n + 1 > j->size) {
		while(j->len + n + 1 > j->size) {
			j->size = j->size ? j->size * 2 : 4096;
		}

		j->buf = xrealloc(j->buf, j->size);
	}

	memcpy(j->buf + j->len, s, n);
	j->len += n;
	j->buf[j->len] = 0;
}

static void json_raw(json_t *j, const char *s) {
	json_append(j, s, strlen(s));
}

static void json_string(json_t *j, const char *s) {
	json_raw(j, "\"");

	for(; s && *s; s++) {
		unsigned char ch = *s;

		if(ch == '"' || ch == '\\') {
			char esc[2] = {'\\', ch};
			json_append(j, esc, 2);
		} else if(ch < 0x20) {
			char esc[8];
			snprintf(esc, sizeof(esc), "\\u%04x", ch);
			json_raw(j, esc);
		} else {
			json_append(j, (const char *)&ch, 1);
		}
	}

	json_raw(j, "\"");
}

static void json_key(json_t *j, bool *first, const char *key) {
	if(!*first) {
		json_raw(j, ",");
	}

	*first = false;
	json_string(j, key);
	json_raw(j, ":");
}

static void json_kv_string(json_t *j, bool *first, const char *key, const char *value) {
	json_key(j, first, key);

	if(value) {
		json_string(j, value);
	} else {
		json_raw(j, "null");
	}
}

static void json_kv_int(json_t *j, bool *first, const char *key, long long value) {
	char num[32];
	snprintf(num, sizeof(num), "%lld", value);
	json_key(j, first, key);
	json_raw(j, num);
}

static void json_kv_bool(json_t *j, bool *first, const char *key, bool value) {
	json_key(j, first, key);
	json_raw(j, value ? "true" : "false");
}

static void json_kv_sockaddr(json_t *j, bool *first, const char *addr_key, const char *port_key, const sockaddr_t *sa) {
	char *host = NULL;
	char *port = NULL;

	if(sa->sa.sa_family == AF_INET || sa->sa.sa_family == AF_INET6) {
		sockaddr2str(sa, &host, &port);
	}

	json_kv_string(j, first, addr_key, host);
	json_kv_string(j, first, port_key, port);
	free(host);
	free(port);
}

static char *build_status_json(void) {
	json_t j = {0};
	bool first = true;

	json_raw(&j, "{");
	json_kv_string(&j, &first, "version", BUILD_VERSION);
	json_kv_string(&j, &first, "name", myself ? myself->name : NULL);
	json_kv_string(&j, &first, "port", myport);
	json_kv_int(&j, &first, "now", now.tv_sec);

	json_key(&j, &first, "nodes");
	json_raw(&j, "[");
	bool first_node = true;

	for splay_each(node_t, n, node_tree) {
		if(!first_node) {
			json_raw(&j, ",");
		}

		first_node = false;
		bool f = true;
		json_raw(&j, "{");
		json_kv_string(&j, &f, "name", n->name);
		json_kv_bool(&j, &f, "myself", n == myself);
		json_kv_bool(&j, &f, "reachable", n->status.reachable);
		json_kv_bool(&j, &f, "validkey", n->status.validkey);
		json_kv_bool(&j, &f, "indirect", n->status.indirect);
		json_kv_bool(&j, &f, "udp_confirmed", n->status.udp_confirmed);
		json_kv_bool(&j, &f, "sptps", n->status.sptps);
		json_kv_bool(&j, &f, "meta_connection", n->connection != NULL && n->connection->edge != NULL);
		json_kv_string(&j, &f, "via", n->via ? n->via->name : NULL);
		json_kv_string(&j, &f, "nexthop", n->nexthop ? n->nexthop->name : NULL);
		json_kv_int(&j, &f, "distance", n->distance);

		if(n->status.reachable && n != myself) {
			json_kv_sockaddr(&j, &f, "address", "port", &n->address);
		}

		json_kv_int(&j, &f, "options", n->options);
		json_kv_int(&j, &f, "compression", n->outcompression);
		json_kv_int(&j, &f, "mtu", n->mtu);
		json_kv_int(&j, &f, "minmtu", n->minmtu);
		json_kv_int(&j, &f, "maxmtu", n->maxmtu);
		json_kv_int(&j, &f, "udp_ping_rtt", n->udp_ping_rtt);
		json_kv_int(&j, &f, "last_state_change", n->last_state_change);
		json_kv_int(&j, &f, "in_packets", (long long)n->in_packets);
		json_kv_int(&j, &f, "in_bytes", (long long)n->in_bytes);
		json_kv_int(&j, &f, "out_packets", (long long)n->out_packets);
		json_kv_int(&j, &f, "out_bytes", (long long)n->out_bytes);

		json_key(&j, &f, "subnets");
		json_raw(&j, "[");
		bool first_subnet = true;

		for splay_each(subnet_t, s, n->subnet_tree) {
			char netstr[MAXNETSTR];

			if(!net2str(netstr, sizeof(netstr), s)) {
				continue;
			}

			if(!first_subnet) {
				json_raw(&j, ",");
			}

			first_subnet = false;
			json_string(&j, netstr);
		}

		json_raw(&j, "]}");
	}

	json_raw(&j, "]");

	json_key(&j, &first, "edges");
	json_raw(&j, "[");
	bool first_edge = true;

	for splay_each(node_t, n, node_tree) {
		for splay_each(edge_t, e, n->edge_tree) {
			if(!first_edge) {
				json_raw(&j, ",");
			}

			first_edge = false;
			bool f = true;
			json_raw(&j, "{");
			json_kv_string(&j, &f, "from", e->from->name);
			json_kv_string(&j, &f, "to", e->to->name);
			json_kv_sockaddr(&j, &f, "address", "port", &e->address);
			json_kv_int(&j, &f, "weight", e->weight);
			json_kv_int(&j, &f, "options", e->options);
			json_raw(&j, "}");
		}
	}

	json_raw(&j, "]");

	json_key(&j, &first, "connections");
	json_raw(&j, "[");
	bool first_conn = true;

	for list_each(connection_t, c, connection_list) {
		if(c->status.control || c == myself->connection) {
			continue;
		}

		if(!first_conn) {
			json_raw(&j, ",");
		}

		first_conn = false;
		bool f = true;
		json_raw(&j, "{");
		json_kv_string(&j, &f, "name", c->name);
		json_kv_string(&j, &f, "hostname", c->hostname);
		json_kv_bool(&j, &f, "outgoing", c->outgoing != NULL);
		json_kv_bool(&j, &f, "active", c->edge != NULL);
		json_kv_bool(&j, &f, "connecting", c->status.connecting);
		json_raw(&j, "}");
	}

	json_raw(&j, "]}");
	return j.buf;
}

/* ---------------------------------------------------------------------
   Control pipe (other threads -> tinc thread)
   --------------------------------------------------------------------- */

static void ctl_handler(void *data, int flags) {
	(void)data;
	(void)flags;
	char cmds[64];
	ssize_t n = read(ctl_read_fd, cmds, sizeof(cmds));

	for(ssize_t i = 0; i < n; i++) {
		switch(cmds[i]) {
		case 'q':
			logger(DEBUG_ALWAYS, LOG_NOTICE, "Stop requested");
			event_exit();
			break;

		case 'r':
			logger(DEBUG_ALWAYS, LOG_NOTICE, "Network change, retrying connections");
			retry();
			break;

		case 'h':
			logger(DEBUG_ALWAYS, LOG_NOTICE, "Reloading configuration");

			if(reload_configuration()) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Reload failed, stopping");
				event_exit();
			}

			break;

		case 's': {
			char *json = build_status_json();
			pthread_mutex_lock(&state_lock);
			free(status_result);
			status_result = json;
			status_done = true;
			pthread_cond_broadcast(&state_cond);
			pthread_mutex_unlock(&state_lock);
			break;
		}

		default:
			break;
		}
	}
}

static bool ctl_send(char cmd) {
	bool sent = false;
	pthread_mutex_lock(&state_lock);

	if(cmd == 'q' && in_run && !running) {
		stop_requested = true;
		sent = true;
	} else if(running && ctl_write_fd >= 0) {
		sent = write(ctl_write_fd, &cmd, 1) == 1;
	}

	pthread_mutex_unlock(&state_lock);
	return sent;
}

void tinc_ios_stop(void) {
	ctl_send('q');
}

void tinc_ios_retry(void) {
	ctl_send('r');
}

void tinc_ios_reload(void) {
	ctl_send('h');
}

char *tinc_ios_status_json(void) {
	char *result = NULL;

	pthread_mutex_lock(&status_request_lock);
	pthread_mutex_lock(&state_lock);

	if(running && ctl_write_fd >= 0) {
		status_done = false;
		char cmd = 's';

		if(write(ctl_write_fd, &cmd, 1) == 1) {
			struct timespec deadline;
			struct timeval tv;
			gettimeofday(&tv, NULL);
			deadline.tv_sec = tv.tv_sec + STATUS_TIMEOUT_SECONDS;
			deadline.tv_nsec = tv.tv_usec * 1000;

			while(!status_done && running) {
				if(pthread_cond_timedwait(&state_cond, &state_lock, &deadline) == ETIMEDOUT) {
					break;
				}
			}

			if(status_done) {
				result = status_result;
				status_result = NULL;
			}
		}
	}

	pthread_mutex_unlock(&state_lock);
	pthread_mutex_unlock(&status_request_lock);
	return result;
}

/* ---------------------------------------------------------------------
   Log rotation: keep at most ~2 MB of logs in the shared container.
   --------------------------------------------------------------------- */

static void log_timer_handler(void *data) {
	(void)data;
	struct stat st;

	if(logfilename && !stat(logfilename, &st) && st.st_size > LOG_ROTATE_SIZE) {
		char old[PATH_MAX];
		snprintf(old, sizeof(old), "%s.1", logfilename);
		rename(logfilename, old);
		reopenlogger();
	}

	timeout_set(&log_timer, &(struct timeval) {
		LOG_ROTATE_INTERVAL, 0
	});
}

/* ---------------------------------------------------------------------
   Startup and shutdown
   --------------------------------------------------------------------- */

/* A phone is rarely reachable from outside, so unless the user chose a
   port, listen on a random one instead of 655 to avoid conflicts. */
static void apply_ios_defaults(void) {
	if(lookup_config(config_tree, "Port")) {
		return;
	}

	char *name = get_name();

	if(name) {
		splay_tree_t *host_config = NULL;
		init_configuration(&host_config);
		bool has_port = read_host_config(host_config, name, false) && lookup_config(host_config, "Port");
		exit_configuration(&host_config);
		free(name);

		if(has_port) {
			return;
		}
	}

	char line[] = "Port = 0";
	config_t *cfg = parse_config_line(line, NULL, 0);

	if(cfg) {
		config_add(config_tree, cfg);
	}
}

static bool make_ctl_pipe(void) {
	int fds[2];

	if(pipe(fds)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not create control pipe: %s", strerror(errno));
		return false;
	}

	for(int i = 0; i < 2; i++) {
		fcntl(fds[i], F_SETFL, fcntl(fds[i], F_GETFL) | O_NONBLOCK);
		fcntl(fds[i], F_SETFD, FD_CLOEXEC);
	}

	ctl_read_fd = fds[0];
	pthread_mutex_lock(&state_lock);
	ctl_write_fd = fds[1];
	pthread_mutex_unlock(&state_lock);
	io_add(&ctl_io, ctl_handler, NULL, ctl_read_fd, IO_READ);
	return true;
}

static void close_ctl_pipe(void) {
	pthread_mutex_lock(&state_lock);
	running = false;

	if(ctl_write_fd >= 0) {
		close(ctl_write_fd);
		ctl_write_fd = -1;
	}

	free(status_result);
	status_result = NULL;
	pthread_cond_broadcast(&state_cond);
	pthread_mutex_unlock(&state_lock);

	if(ctl_read_fd >= 0) {
		io_del(&ctl_io);
		close(ctl_read_fd);
		ctl_read_fd = -1;
	}
}

int tinc_ios_run(const tinc_ios_options *options) {
	if(!options || !options->confbase) {
		return 1;
	}

	pthread_mutex_lock(&state_lock);

	if(in_run) {
		pthread_mutex_unlock(&state_lock);
		return 1;
	}

	in_run = true;
	stop_requested = false;
	pthread_mutex_unlock(&state_lock);

	int status = 1;
	bool setup_attempted = false;

	/* tincd ignores SIGPIPE in detach(); a dead peer must not kill the extension. */
	signal(SIGPIPE, SIG_IGN);

	program_name = "tincd";
	myself = NULL;
	do_detach = false;
	confbase = xstrdup(options->confbase);
	netname = NULL;
	xasprintf(&pidfilename, "%s" SLASH "pid", confbase);
	logfilename = options->logfile ? xstrdup(options->logfile) : NULL;
	make_names(true);

	openlogger("tinc", logfilename ? LOGMODE_FILE : LOGMODE_STDERR);
	debug_level = options->debug_level >= 0 ? options->debug_level : DEBUG_NOTHING;

	cmdline_conf = list_alloc((list_action_t)free_config);
	init_configuration(&config_tree);

	gettimeofday(&now, NULL);
	srand(now.tv_sec + now.tv_usec);
	crypto_init();

	if(!read_server_config()) {
		goto end;
	}

	if(options->debug_level < 0) {
		get_config_int(lookup_config(config_tree, "LogLevel"), &debug_level);
	}

	logger(DEBUG_ALWAYS, LOG_NOTICE, "tinc %s (protocol %d.%d) starting on iOS", BUILD_VERSION, PROT_MAJOR, PROT_MINOR);

	apply_ios_defaults();
	tinc_ios_tun_fd = options->tun_fd;

	if(!make_ctl_pipe()) {
		goto end;
	}

	setup_attempted = true;

	if(!setup_network()) {
		goto end;
	}

	pthread_mutex_lock(&state_lock);
	running = true;
	bool stop_now = stop_requested;
	pthread_mutex_unlock(&state_lock);

	if(stop_now) {
		status = 0;
		goto end;
	}

	logger(DEBUG_ALWAYS, LOG_NOTICE, "Ready");

	if(options->ready) {
		options->ready(options->context);
	}

	try_outgoing_connections();

	if(logfilename) {
		timeout_add(&log_timer, log_timer_handler, NULL, &(struct timeval) {
			LOG_ROTATE_INTERVAL, 0
		});
	}

	status = main_loop();

	timeout_del(&log_timer);

end:
	close_ctl_pipe();

	/* Like tincd, tear down even after a failed setup_network(). */
	if(setup_attempted) {
		close_network_connections();

		/* tincd exits after this; we may run again, so drop pointers it freed. */
		outgoing_list = NULL;
		myport = NULL;
		scriptinterpreter = NULL;
		scriptextension = NULL;
		myself = NULL;
	}

	/* The device did not get as far as taking ownership of the fd. */
	if(tinc_ios_tun_fd >= 0) {
		close(tinc_ios_tun_fd);
		tinc_ios_tun_fd = -1;
	}

	logger(DEBUG_ALWAYS, LOG_NOTICE, "Terminating");

	crypto_exit();
	exit_configuration(&config_tree);
	list_delete_list(cmdline_conf);
	cmdline_conf = NULL;

	closelogger();
	openlogger("tinc", LOGMODE_STDERR);
	free_names();

	pthread_mutex_lock(&state_lock);
	in_run = false;
	pthread_mutex_unlock(&state_lock);

	return status;
}
