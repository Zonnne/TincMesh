/*
    ios_device.c -- packet device backed by a socketpair to NEPacketTunnelFlow

    Based on fd_device.c (the Android backend). The Swift side of the
    socketpair exchanges raw IPv4/IPv6 packets with NEPacketTunnelFlow, one
    datagram per packet. tinc works with Ethernet frames internally, so a
    fake Ethernet header carrying only the EtherType is added on read and
    stripped on write. Only router mode (Mode = router) is possible, as
    iOS offers no layer-2 tunnel.

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

#include "tinc_ios_private.h"

int device_fd = -1;
char *device = NULL;
char *iface = NULL;

static bool setup_device(void) {
	if(routing_mode != RMODE_ROUTER) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Only Mode = router is supported on iOS (no layer 2 tunnel available)!");
		return false;
	}

	if(tinc_ios_tun_fd < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "No packet tunnel file descriptor available!");
		return false;
	}

	device_fd = tinc_ios_tun_fd;
	tinc_ios_tun_fd = -1;

	fcntl(device_fd, F_SETFL, fcntl(device_fd, F_GETFL) | O_NONBLOCK);
#ifdef FD_CLOEXEC
	fcntl(device_fd, F_SETFD, FD_CLOEXEC);
#endif

	free(device);
	free(iface);
	device = xstrdup("NEPacketTunnelFlow");
	iface = xstrdup("utun");

	logger(DEBUG_ALWAYS, LOG_INFO, "%s is an %s", device, "iOS packet tunnel");
	return true;
}

static void close_device(void) {
	if(device_fd >= 0) {
		close(device_fd);
	}

	device_fd = -1;
	free(device);
	free(iface);
	device = NULL;
	iface = NULL;
}

static bool read_packet(vpn_packet_t *packet) {
	for(;;) {
		ssize_t lenin = read(device_fd, DATA(packet) + ETH_HLEN, MTU - ETH_HLEN);

		if(lenin < 0 && errno == EINTR) {
			continue;
		}

		if(lenin <= 0) {
			/* Spurious wakeup: handle_device_data() only backs off briefly. */
			if(lenin < 0 && errno == EAGAIN) {
				return false;
			}

			logger(DEBUG_ALWAYS, LOG_ERR, "Error while reading from %s: %s", device, lenin ? strerror(errno) : "end of file");
			event_exit();
			return false;
		}

		uint16_t ethertype;

		switch(DATA(packet)[ETH_HLEN] >> 4) {
		case 4:
			ethertype = ETH_P_IP;
			break;

		case 6:
			ethertype = ETH_P_IPV6;
			break;

		default:
			/* Not an IP packet; skip it rather than counting it as a device error. */
			logger(DEBUG_TRAFFIC, LOG_ERR, "Unknown IP version while reading packet from %s!", device);
			continue;
		}

		memset(DATA(packet), 0, ETH_HLEN - ETHER_TYPE_LEN);
		DATA(packet)[ETH_HLEN - ETHER_TYPE_LEN] = ethertype >> 8;
		DATA(packet)[ETH_HLEN - ETHER_TYPE_LEN + 1] = ethertype & 0xff;
		packet->len = lenin + ETH_HLEN;

		logger(DEBUG_TRAFFIC, LOG_DEBUG, "Read packet of %d bytes from %s", packet->len, device);
		return true;
	}
}

static bool write_packet(vpn_packet_t *packet) {
	if(packet->len <= ETH_HLEN) {
		return false;
	}

	logger(DEBUG_TRAFFIC, LOG_DEBUG, "Writing packet of %d bytes to %s", packet->len, device);

	if(write(device_fd, DATA(packet) + ETH_HLEN, packet->len - ETH_HLEN) < 0) {
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
