/*
    policy.h -- rule-based routing for the iOS packet tunnel

    Shadowrocket-style rules choose, per connection, which tinc node
    carries traffic (for example one exit node for some sites and another
    for others). Domain rules work through fake IPs: queries for matching
    names are answered by a DNS responder inside the tunnel with an
    address from 198.18.0.0/15, the real address is resolved through the
    chosen node, and packets are translated between the two on the way
    in and out. IP-CIDR rules and FINAL apply to real addresses directly.

    Everything except policy_parse()/policy_free()/policy_summary_json()
    must be called on the tinc thread.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#ifndef TINC_IOS_POLICY_H
#define TINC_IOS_POLICY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct node_t;

typedef struct policy_t policy_t;

/* Address of the DNS responder inside the tunnel, and the fake address range. */
#define POLICY_DNS_ADDRESS "198.18.0.2"
#define POLICY_FAKE_RANGE "198.18.0.0/15"

/* Parses a rules file. Returns NULL and fills error (with the line number) on failure. */
policy_t *policy_parse(const char *text, char *error, size_t error_len);
void policy_free(policy_t *policy);

/* JSON describing what the tunnel must route and which DNS names to capture. */
char *policy_summary_json(const policy_t *policy);

/* Packet I/O provided by the device layer. */
typedef struct policy_io_t {
	/* Deliver a raw IP packet to the apps (into NEPacketTunnelFlow). */
	void (*write_to_app)(const uint8_t *ip, size_t len);
	/* Route a raw IP packet into the mesh as if it came from the device, optionally forced to a node. */
	void (*inject)(const uint8_t *ip, size_t len, struct node_t *via);
} policy_io_t;

/* Takes ownership of policy (NULL disables rules) and resets all translation state. */
void policy_install(policy_t *policy, const policy_io_t *io);
bool policy_active(void);
void policy_shutdown(void);

typedef enum policy_verdict_t {
	POLICY_FORWARD,   /* route the (possibly rewritten) packet; *via may name a node */
	POLICY_CONSUMED,  /* handled or dropped by the policy engine */
} policy_verdict_t;

/* Packet from the apps, before routing. May rewrite the packet in place. */
policy_verdict_t policy_outbound(uint8_t *ip, size_t len, struct node_t **via);

/* Packet from the mesh, before delivery to the apps. May rewrite it in place. */
policy_verdict_t policy_inbound(uint8_t *ip, size_t len);

/* JSON object with counters and group selections, for the status snapshot. */
char *policy_status_json(void);

#endif
