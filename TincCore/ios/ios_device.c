/*
    ios_device.c -- packet device backed by a socketpair to NEPacketTunnelFlow

    Based on fd_device.c (the Android backend). The Swift side of the
    socketpair exchanges raw IPv4/IPv6 packets with NEPacketTunnelFlow, one
    datagram per packet. tinc works with Ethernet frames internally, so a
    fake Ethernet header carrying only the EtherType is added on read and
    stripped on write. Only router mode (Mode = router) is possible, as
    iOS offers no layer-2 tunnel.

    This device registers its own read handler instead of tinc's
    handle_device_data(), so that every packet passes through the policy
    engine (policy.c) on its way in and out, and so that packets consumed
    by it (DNS) are not mistaken for device errors.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "../tinc/system.h"

#include "../tinc/conf.h"
#include "../tinc/device.h"
#include "../tinc/ethernet.h"
#include "../tinc/logger.h"
#include "../tinc/net.h"
#include "../tinc/route.h"
#include "../tinc/xalloc.h"

#include "policy.h"
#include "tinc_ios_private.h"

/* tinc only adds its own read handler when device_fd >= 0; this device keeps
   device_fd at -1 and uses tun_fd with its own handler instead. */
int device_fd = -1;
char *device = NULL;
char *iface = NULL;

static int tun_fd = -1;
static io_t tun_io;

/* Set while routing a packet that a policy rule assigned to a node (see route.c). */
extern node_t *tinc_ios_route_override;

#define READ_BATCH 64

static void set_ethertype(vpn_packet_t *packet, uint16_t ethertype) {
	memset(DATA(packet), 0, ETH_HLEN - ETHER_TYPE_LEN);
	DATA(packet)[ETH_HLEN - ETHER_TYPE_LEN] = ethertype >> 8;
	DATA(packet)[ETH_HLEN - ETHER_TYPE_LEN + 1] = ethertype & 0xff;
}

static void route_from_device(vpn_packet_t *packet, node_t *via) {
	myself->in_packets++;
	myself->in_bytes += packet->len;
	tinc_ios_route_override = via;
	route(myself, packet);
	tinc_ios_route_override = NULL;
}

static void tun_handler(void *data, int flags) {
	(void)data;
	(void)flags;

	for(int i = 0; i < READ_BATCH; i++) {
		vpn_packet_t packet;
		packet.offset = DEFAULT_PACKET_OFFSET;
		packet.priority = 0;

		ssize_t lenin = read(tun_fd, DATA(&packet) + ETH_HLEN, MTU - ETH_HLEN);

		if(lenin < 0 && errno == EINTR) {
			continue;
		}

		if(lenin < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			return;
		}

		if(lenin <= 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Error while reading from %s: %s", device, lenin ? strerror(errno) : "end of file");
			event_exit();
			return;
		}

		uint8_t *ip = DATA(&packet) + ETH_HLEN;

		switch(ip[0] >> 4) {
		case 4:
			set_ethertype(&packet, ETH_P_IP);
			break;

		case 6:
			set_ethertype(&packet, ETH_P_IPV6);
			break;

		default:
			logger(DEBUG_TRAFFIC, LOG_ERR, "Unknown IP version while reading packet from %s!", device);
			continue;
		}

		packet.len = lenin + ETH_HLEN;
		logger(DEBUG_TRAFFIC, LOG_DEBUG, "Read packet of %d bytes from %s", packet.len, device);

		node_t *via = NULL;

		if(policy_outbound(ip, lenin, &via) == POLICY_CONSUMED) {
			continue;
		}

		route_from_device(&packet, via);
	}
}

/* Policy engine I/O: answers to apps and packets it originates (DNS through a node). */
static void policy_write_to_app(const uint8_t *ip, size_t len) {
	if(tun_fd >= 0 && write(tun_fd, ip, len) < 0 && errno != EAGAIN && errno != ENOBUFS) {
		logger(DEBUG_TRAFFIC, LOG_ERR, "Error while writing to %s: %s", device, strerror(errno));
	}
}

static void policy_inject(const uint8_t *ip, size_t len, node_t *via) {
	vpn_packet_t packet;
	packet.offset = DEFAULT_PACKET_OFFSET;
	packet.priority = 0;

	if(len + ETH_HLEN > MTU || len < 1) {
		return;
	}

	memcpy(DATA(&packet) + ETH_HLEN, ip, len);
	set_ethertype(&packet, (ip[0] >> 4) == 6 ? ETH_P_IPV6 : ETH_P_IP);
	packet.len = len + ETH_HLEN;
	route_from_device(&packet, via);
}

const policy_io_t tinc_ios_policy_io = {
	.write_to_app = policy_write_to_app,
	.inject = policy_inject,
};

static bool setup_device(void) {
	if(routing_mode != RMODE_ROUTER) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Only Mode = router is supported on iOS (no layer 2 tunnel available)!");
		return false;
	}

	if(tinc_ios_tun_fd < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "No packet tunnel file descriptor available!");
		return false;
	}

	tun_fd = tinc_ios_tun_fd;
	tinc_ios_tun_fd = -1;

	fcntl(tun_fd, F_SETFL, fcntl(tun_fd, F_GETFL) | O_NONBLOCK);
#ifdef FD_CLOEXEC
	fcntl(tun_fd, F_SETFD, FD_CLOEXEC);
#endif

	free(device);
	free(iface);
	device = xstrdup("NEPacketTunnelFlow");
	iface = xstrdup("utun");

	io_add(&tun_io, tun_handler, NULL, tun_fd, IO_READ);

	logger(DEBUG_ALWAYS, LOG_INFO, "%s is an %s", device, "iOS packet tunnel");
	return true;
}

static void close_device(void) {
	if(tun_io.cb) {
		io_del(&tun_io);
	}

	if(tun_fd >= 0) {
		close(tun_fd);
	}

	tun_fd = -1;
	free(device);
	free(iface);
	device = NULL;
	iface = NULL;
}

/* Never called: this device has its own read handler. */
static bool read_packet(vpn_packet_t *packet) {
	(void)packet;
	return false;
}

static bool write_packet(vpn_packet_t *packet) {
	if(packet->len <= ETH_HLEN || tun_fd < 0) {
		return false;
	}

	uint8_t *ip = DATA(packet) + ETH_HLEN;
	size_t len = packet->len - ETH_HLEN;

	if(policy_inbound(ip, len) == POLICY_CONSUMED) {
		return true;
	}

	logger(DEBUG_TRAFFIC, LOG_DEBUG, "Writing packet of %d bytes to %s", packet->len, device);

	if(write(tun_fd, ip, len) < 0) {
		/* A full socket buffer means the extension is not keeping up; drop like a real tun would. */
		if(errno != EAGAIN && errno != ENOBUFS && errno != EINTR) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Error while writing to %s: %s", device, strerror(errno));
		}

		return false;
	}

	return true;
}

const devops_t os_devops = {
	.setup = setup_device,
	.close = close_device,
	.read = read_packet,
	.write = write_packet,
};
