/*
    ios_script.c -- replacement for script.c on iOS

    iOS apps cannot spawn processes, so tinc-up, tinc-down, host-up,
    subnet-up and friends cannot run. Interface addresses and routes that
    tinc-up would normally configure are applied by the packet tunnel
    provider through NEPacketTunnelNetworkSettings instead.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "../tinc/system.h"

#include "../tinc/logger.h"
#include "../tinc/script.h"
#include "../tinc/xalloc.h"

int environment_add(environment_t *env, const char *format, ...) {
	if(env->n >= env->size) {
		env->size = env->n ? env->n * 2 : 8;
		env->entries = xrealloc(env->entries, env->size * sizeof(*env->entries));
	}

	if(format) {
		va_list ap;
		va_start(ap, format);

		if(vasprintf(&env->entries[env->n], format, ap) < 0) {
			env->entries[env->n] = NULL;
		}

		va_end(ap);
	} else {
		env->entries[env->n] = NULL;
	}

	return env->n++;
}

int environment_placeholder(environment_t *env) {
	return environment_add(env, NULL);
}

void environment_update(environment_t *env, int pos, const char *format, ...) {
	free(env->entries[pos]);
	va_list ap;
	va_start(ap, format);

	if(vasprintf(&env->entries[pos], format, ap) < 0) {
		env->entries[pos] = NULL;
	}

	va_end(ap);
}

void environment_init(environment_t *env) {
	env->n = 0;
	env->size = 0;
	env->entries = NULL;
}

void environment_exit(environment_t *env) {
	for(int i = 0; i < env->n; i++) {
		free(env->entries[i]);
	}

	free(env->entries);
	env->entries = NULL;
	env->n = env->size = 0;
}

bool execute_script(const char *name, environment_t *env) {
	(void)env;
	logger(DEBUG_STATUS, LOG_INFO, "Not executing script %s: scripts are not supported on iOS", name);
	return true;
}
