/*
    tinc_ios.h -- C API for running tinc 1.1 inside an iOS app/extension.

    The functions in this header are the only ones the Swift side uses.
    tincd normally runs as its own process with a TUN device; here it runs
    on a dedicated thread inside the Network Extension, and the "device" is
    one end of an AF_UNIX/SOCK_DGRAM socketpair whose other end is pumped
    to and from NEPacketTunnelFlow by Swift. Each datagram is one raw IPv4
    or IPv6 packet (no utun AF header, no Ethernet header).

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#ifndef TINC_IOS_H
#define TINC_IOS_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Version string of the embedded tinc, e.g. "1.1pre18". */
const char *tinc_ios_version(void);

/* ---------------------------------------------------------------------
   Daemon
   --------------------------------------------------------------------- */

/* Called once on the tinc thread when the network is set up and the main
   loop is about to start. */
typedef void (*tinc_ios_ready_cb)(void *context);

typedef struct tinc_ios_options {
	const char *confbase;    /* directory containing tinc.conf, hosts/, ed25519_key.priv */
	const char *logfile;     /* log file path, or NULL to log to stderr */
	int tun_fd;              /* tinc's end of the packet socketpair; tinc takes ownership */
	int debug_level;         /* -1 = use LogLevel from tinc.conf (default 0) */
	tinc_ios_ready_cb ready; /* optional */
	void *context;           /* passed to ready */
} tinc_ios_options;

/* Runs tincd's setup and main loop on the calling thread. Blocks until
   tinc_ios_stop() is called or a fatal error occurs. Returns 0 on a clean
   stop, non-zero on failure. Only one instance may run per process. */
int tinc_ios_run(const tinc_ios_options *options);

/* The following are safe to call from any thread while tinc_ios_run() is
   executing; they are no-ops otherwise. */

/* Ask the main loop to exit (equivalent to SIGTERM for tincd). */
void tinc_ios_stop(void);

/* Retry all outgoing connections now (equivalent to SIGALRM / `tinc retry`).
   Call this when the device's network path changes. */
void tinc_ios_retry(void);

/* Re-read tinc.conf and host files (equivalent to SIGHUP / `tinc reload`). */
void tinc_ios_reload(void);

/* Returns a malloc()ed JSON snapshot of the mesh (nodes, edges, subnets,
   traffic counters), or NULL if tinc is not running. Free with free(). */
char *tinc_ios_status_json(void);

/* ---------------------------------------------------------------------
   Keys and configuration helpers (usable from the app process)
   --------------------------------------------------------------------- */

/* Generates a new Ed25519 key pair, writes the private key in tinc's PEM
   format to private_key_path (mode 0600) and returns the public key in
   tinc's base64 encoding (as used for `Ed25519PublicKey = ...`).
   Returns NULL on failure. Free the result with free(). */
char *tinc_ios_generate_key(const char *private_key_path);

/* Reads a tinc Ed25519 private key file and returns its public key in
   tinc's base64 encoding, or NULL. Free the result with free(). */
char *tinc_ios_public_key_from_private(const char *private_key_path);

/* Returns true if name is a valid tinc node name (only [A-Za-z0-9_]). */
bool tinc_ios_check_id(const char *name);

/* ---------------------------------------------------------------------
   Invitations (`tinc join`)
   --------------------------------------------------------------------- */

/* Accepts a tinc invitation URL of the form host[:port]/<48 chars> by
   connecting to the inviting node, running the SPTPS invitation protocol,
   and writing tinc.conf, the hosts directory, and a fresh ed25519_key.priv into
   confbase (which must not already contain a tinc.conf).

   On success returns a malloc()ed JSON object:
     {"name": "...", "netname": "...", "ifconfig": ["10.0.0.5/24", ...],
      "routes": ["10.1.0.0/16", ...]}
   where ifconfig/routes are the Ifconfig and Route statements from the
   invitation (normally turned into a tinc-up script, which iOS cannot run).
   On failure returns NULL and writes a message to error (if non-NULL).
   This call blocks on network I/O; never call it on the main thread. */
char *tinc_ios_join(const char *confbase, const char *invitation_url,
                    int timeout_seconds, char *error, size_t error_len);

/* Creates an invitation like `tinc invite`, for a node that can be reached
   by the invitee (normally a server, but any reachable node works).

   confbase: this node's configuration (must contain tinc.conf with Name)
   netname:  optional NetName suggested to the invitee (may be NULL)
   invitee:  the new node's name (must not have a host file yet)
   address:  how the invitee reaches us: "host" or "host:port"
   extra:    optional extra lines for the invitee's configuration, such as
             "Ifconfig = 10.0.0.7/24\nSubnet = 10.0.0.7/32" (may be NULL)

   Writes invitations/<id> (and invitations/ed25519_key.priv on first use)
   and returns the malloc()ed invitation URL, or NULL with error filled in.
   If tinc is running in this process, call tinc_ios_reload() afterwards so
   it loads a newly created invitation key. */
char *tinc_ios_invite(const char *confbase, const char *netname, const char *invitee,
                      const char *address, const char *extra, char *error, size_t error_len);

#ifdef __cplusplus
}
#endif

#endif
