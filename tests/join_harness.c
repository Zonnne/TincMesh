/*
    join_harness.c -- command-line access to the TincCore key/invite/join API

    Usage:
      join_harness keygen <private-key-path>
          Generate a key; print the public key. Also checks that reading the
          public key back from the private key file gives the same result.
      join_harness invite <confbase> <invitee> <address> [<extra lines>]
          Print an invitation URL.
      join_harness join <confbase> <url>
          Accept an invitation; print the result JSON.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tinc_ios.h"

int main(int argc, char *argv[]) {
	char error[1024] = "";

	if(argc == 3 && !strcmp(argv[1], "keygen")) {
		char *pub = tinc_ios_generate_key(argv[2]);
		char *again = pub ? tinc_ios_public_key_from_private(argv[2]) : NULL;

		if(!pub || !again || strcmp(pub, again)) {
			fprintf(stderr, "key generation failed\n");
			return 1;
		}

		puts(pub);
		free(pub);
		free(again);
		return 0;
	}

	if((argc == 5 || argc == 6) && !strcmp(argv[1], "invite")) {
		char *url = tinc_ios_invite(argv[2], "testnet", argv[3], argv[4], argc == 6 ? argv[5] : NULL, error, sizeof(error));

		if(!url) {
			fprintf(stderr, "invite failed: %s\n", error);
			return 1;
		}

		puts(url);
		free(url);
		return 0;
	}

	if(argc == 4 && !strcmp(argv[1], "join")) {
		char *json = tinc_ios_join(argv[2], argv[3], 10, error, sizeof(error));

		if(!json) {
			fprintf(stderr, "join failed: %s\n", error);
			return 1;
		}

		puts(json);
		free(json);
		return 0;
	}

	fprintf(stderr, "usage: %s keygen <path> | invite <confbase> <name> <address> [extra] | join <confbase> <url>\n", argv[0]);
	return 2;
}
