/*
    ios_control.c -- replacement for control.c on iOS

    tincd normally exposes a UNIX control socket (used by the `tinc` CLI)
    and writes a pid file. Inside an iOS extension there is no CLI, and
    container paths are too long for sockaddr_un, so control requests are
    instead served in-process through tinc_ios.c. This file keeps the
    symbols the rest of tincd links against and rejects any CONTROL
    request arriving over the network.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "../tinc/system.h"

#include "../tinc/connection.h"
#include "../tinc/control.h"
#include "../tinc/crypto.h"
#include "../tinc/logger.h"
#include "../tinc/net.h"
#include "../tinc/protocol.h"
#include "../tinc/utils.h"

/* id_h() treats a peer presenting "^<controlcookie>" as a control client,
   so the cookie must always be an unguessable secret, never empty. */
char controlcookie[65];

bool control_h(connection_t *c, const char *request) {
	(void)request;
	logger(DEBUG_ALWAYS, LOG_ERR, "Unauthorized control request from %s (%s)", c->name, c->hostname);
	return false;
}

bool init_control(void) {
	randomize(controlcookie, sizeof(controlcookie) / 2);
	bin2hex(controlcookie, controlcookie, sizeof(controlcookie) / 2);
	return true;
}

void exit_control(void) {
}
