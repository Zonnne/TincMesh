/*
    tinc_ios_util.c -- key generation and small helpers for the iOS app

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "../tinc/system.h"

#include <pthread.h>

#include "../tinc/crypto.h"
#include "../tinc/ecdsa.h"
#include "../tinc/ecdsagen.h"
#include "../tinc/utils.h"
#include "../tinc/xalloc.h"

#include "tinc_ios.h"
#include "tinc_ios_util.h"

static pthread_once_t crypto_once = PTHREAD_ONCE_INIT;

void tinc_ios_crypto_init(void) {
	pthread_once(&crypto_once, crypto_init);
}

char *tinc_ios_json_quote(const char *s) {
	size_t len = s ? strlen(s) : 0;
	char *out = xmalloc(len * 6 + 3);
	char *o = out;
	*o++ = '"';

	for(size_t i = 0; i < len; i++) {
		unsigned char ch = s[i];

		if(ch == '"' || ch == '\\') {
			*o++ = '\\';
			*o++ = ch;
		} else if(ch < 0x20) {
			o += sprintf(o, "\\u%04x", ch);
		} else {
			*o++ = ch;
		}
	}

	*o++ = '"';
	*o = 0;
	return out;
}

bool tinc_ios_check_id(const char *name) {
	return name && check_id(name);
}

char *tinc_ios_generate_key(const char *private_key_path) {
	tinc_ios_crypto_init();

	ecdsa_t *key = ecdsa_generate();

	if(!key) {
		return NULL;
	}

	char *pubkey = NULL;
	int fd = open(private_key_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	FILE *f = fd >= 0 ? fdopen(fd, "w") : NULL;

	if(f) {
		if(ecdsa_write_pem_private_key(key, f)) {
			pubkey = ecdsa_get_base64_public_key(key);
		}

		if(fclose(f)) {
			free(pubkey);
			pubkey = NULL;
		}
	} else if(fd >= 0) {
		close(fd);
	}

	ecdsa_free(key);
	return pubkey;
}

char *tinc_ios_public_key_from_private(const char *private_key_path) {
	FILE *f = fopen(private_key_path, "r");

	if(!f) {
		return NULL;
	}

	ecdsa_t *key = ecdsa_read_pem_private_key(f);
	fclose(f);

	if(!key) {
		return NULL;
	}

	char *pubkey = ecdsa_get_base64_public_key(key);
	ecdsa_free(key);
	return pubkey;
}
