/*
    tinc_invite.c -- `tinc invite` for iOS

    A port of cmd_invite() from tinc's invitation.c. The running tincd
    serves the invitation files written here; tinc_join.c (or the tinc CLI
    on any other platform) consumes them.

    Copyright (C) 2013-2021 Guus Sliepen <guus@tinc-vpn.org> (invitation.c)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "../tinc/system.h"

#include "../tinc/crypto.h"
#include "../tinc/ecdsa.h"
#include "../tinc/ecdsagen.h"
#include "../tinc/ed25519/sha512.h"
#include "../tinc/protocol.h"
#include "../tinc/utils.h"
#include "../tinc/xalloc.h"

#include "tinc_ios.h"
#include "tinc_ios_util.h"

#define INVITATION_LIFETIME 604800 /* one week, as in tinc */

static void set_error(char *error, size_t error_len, const char *format, ...) {
	if(!error || !error_len) {
		return;
	}

	va_list ap;
	va_start(ap, format);
	vsnprintf(error, error_len, format, ap);
	va_end(ap);
}

/* Reads "Name = x" from tinc.conf. */
static bool read_my_name(const char *confbase, char *name, size_t len) {
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s" SLASH "tinc.conf", confbase);
	FILE *f = fopen(path, "r");

	if(!f) {
		return false;
	}

	char line[1024];
	bool found = false;

	while(!found && fgets(line, sizeof(line), f)) {
		char *var = line + strspn(line, " \t");
		size_t varlen = strcspn(var, " \t=");

		if(varlen != 4 || strncasecmp(var, "Name", 4)) {
			continue;
		}

		char *value = var + varlen;
		value += strspn(value, " \t");

		if(*value == '=') {
			value++;
			value += strspn(value, " \t");
		}

		value[strcspn(value, " \t\r\n")] = 0;

		if(check_id(value) && strlen(value) < len) {
			strcpy(name, value);
			found = true;
		}
	}

	fclose(f);
	return found;
}

/* Copies the lines of tinc.conf that the invitee must share with us. */
static void copy_mode_and_broadcast(const char *confbase, FILE *out) {
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s" SLASH "tinc.conf", confbase);
	FILE *tc = fopen(path, "r");

	if(!tc) {
		return;
	}

	char buf[1024];

	while(fgets(buf, sizeof(buf), tc)) {
		if((!strncasecmp(buf, "Mode", 4) && strchr(" \t=", buf[4]))
		                || (!strncasecmp(buf, "Broadcast", 9) && strchr(" \t=", buf[9]))) {
			fputs(buf, out);

			if(!strchr(buf, '\n')) {
				fputc('\n', out);
			}
		}
	}

	fclose(tc);
}

static int count_valid_invitations(const char *dirname) {
	DIR *dir = opendir(dirname);

	if(!dir) {
		return 0;
	}

	int count = 0;
	time_t deadline = time(NULL) - INVITATION_LIFETIME;
	struct dirent *ent;

	while((ent = readdir(dir))) {
		if(strlen(ent->d_name) != 24) {
			continue;
		}

		char invname[PATH_MAX];
		struct stat st;
		snprintf(invname, sizeof(invname), "%s" SLASH "%s", dirname, ent->d_name);

		if(!stat(invname, &st)) {
			if(deadline < st.st_mtime) {
				count++;
			} else {
				unlink(invname);
			}
		}
	}

	closedir(dir);
	return count;
}

static ecdsa_t *load_or_create_invitation_key(const char *keyfile, int outstanding) {
	if(!outstanding) {
		unlink(keyfile);
	}

	FILE *f = fopen(keyfile, "r");

	if(f) {
		ecdsa_t *key = ecdsa_read_pem_private_key(f);
		fclose(f);
		return key;
	}

	ecdsa_t *key = ecdsa_generate();
	int fd = open(keyfile, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	f = fd >= 0 ? fdopen(fd, "w") : NULL;

	if(!key || !f || !ecdsa_write_pem_private_key(key, f)) {
		if(f) {
			fclose(f);
		} else if(fd >= 0) {
			close(fd);
		}

		unlink(keyfile);
		ecdsa_free(key);
		return NULL;
	}

	fclose(f);
	return key;
}

char *tinc_ios_invite(const char *confbase, const char *netname, const char *invitee,
                      const char *address, const char *extra, char *error, size_t error_len) {
	tinc_ios_crypto_init();

	if(error && error_len) {
		*error = 0;
	}

	if(!invitee || !check_id(invitee)) {
		set_error(error, error_len, "Invalid name for node");
		return NULL;
	}

	if(!address || !*address) {
		set_error(error, error_len, "An address the invitee can reach this node at is required");
		return NULL;
	}

	char myname[MAX_STRING_SIZE];

	if(!read_my_name(confbase, myname, sizeof(myname))) {
		set_error(error, error_len, "Could not find a valid Name in tinc.conf");
		return NULL;
	}

	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s" SLASH "hosts" SLASH "%s", confbase, invitee);

	if(!access(path, F_OK)) {
		set_error(error, error_len, "A host config file for %s already exists", invitee);
		return NULL;
	}

	char invdir[PATH_MAX];
	snprintf(invdir, sizeof(invdir), "%s" SLASH "invitations", confbase);

	if(mkdir(invdir, 0700) && errno != EEXIST) {
		set_error(error, error_len, "Could not create invitations directory: %s", strerror(errno));
		return NULL;
	}

	char keyfile[PATH_MAX];
	snprintf(keyfile, sizeof(keyfile), "%s" SLASH "ed25519_key.priv", invdir);
	ecdsa_t *key = load_or_create_invitation_key(keyfile, count_valid_invitations(invdir));

	if(!key) {
		set_error(error, error_len, "Could not create the invitation key");
		return NULL;
	}

	/* The URL carries a hash of the invitation key and a random cookie;
	   the file name is a hash of both so it does not reveal the cookie. */
	char hash[64];
	char *fingerprint = ecdsa_get_base64_public_key(key);
	ecdsa_free(key);
	sha512(fingerprint, strlen(fingerprint), hash);
	b64encode_urlsafe(hash, hash, 18);

	char cookie[64];
	randomize(cookie, 18);

	size_t fplen = strlen(fingerprint);
	char *buf = xmalloc(18 + fplen);
	char cookiehash[64];
	memcpy(buf, cookie, 18);
	memcpy(buf + 18, fingerprint, fplen);
	sha512(buf, 18 + fplen, cookiehash);
	b64encode_urlsafe(cookiehash, cookiehash, 18);
	free(buf);
	free(fingerprint);

	b64encode_urlsafe(cookie, cookie, 18);

	snprintf(path, sizeof(path), "%s" SLASH "%s", invdir, cookiehash);
	int ifd = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
	FILE *f = ifd >= 0 ? fdopen(ifd, "w") : NULL;

	if(!f) {
		set_error(error, error_len, "Could not create invitation file: %s", strerror(errno));

		if(ifd >= 0) {
			close(ifd);
		}

		return NULL;
	}

	fprintf(f, "Name = %s\n", invitee);

	if(netname && *netname && check_netname(netname, true)) {
		fprintf(f, "NetName = %s\n", netname);
	}

	fprintf(f, "ConnectTo = %s\n", myname);
	copy_mode_and_broadcast(confbase, f);

	if(extra && *extra) {
		fputs(extra, f);

		if(extra[strlen(extra) - 1] != '\n') {
			fputc('\n', f);
		}
	}

	/* Append our own host file so the invitee knows how to reach and verify us. */
	fprintf(f, "#---------------------------------------------------------------#\n");
	fprintf(f, "Name = %s\n", myname);

	char hostfile[PATH_MAX];
	snprintf(hostfile, sizeof(hostfile), "%s" SLASH "hosts" SLASH "%s", confbase, myname);
	FILE *hf = fopen(hostfile, "r");

	if(hf) {
		char line[4096];

		while(fgets(line, sizeof(line), hf)) {
			fputs(line, f);
		}

		fclose(hf);
	}

	if(fclose(f)) {
		set_error(error, error_len, "Could not write invitation file: %s", strerror(errno));
		unlink(path);
		return NULL;
	}

	char *url;
	xasprintf(&url, "%s/%s%s", address, hash, cookie);
	return url;
}
