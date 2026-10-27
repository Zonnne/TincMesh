/*
    ios_process.c -- replacement for process.c on iOS

    tincd's process.c handles daemonizing, signals and Windows services.
    Under iOS the daemon runs on a thread of the packet tunnel extension
    and never forks, so only the shared flags are kept.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "../tinc/system.h"

#include "../tinc/process.h"

bool do_detach = false;
bool sigalrm = false;

void setup_signals(void) {
}

bool detach(void) {
	return true;
}

bool kill_other(int signal) {
	(void)signal;
	return false;
}
