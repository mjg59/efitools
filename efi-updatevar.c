/*
 * Copyright 2013 <James.Bottomley@HansenPartnership.com>
 *
 * see COPYING file
 */

#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <openssl/x509.h>

#define __STDC_VERSION__ 199901L
#include <efi.h>

#include <kernel_efivars.h>
#include <guid.h>
#include <sha256.h>
#include <version.h>
#include "efiauthenticated.h"

#define ARRAY_SIZE(a) (sizeof (a) / sizeof ((a)[0]))

static void
usage(const char *progname)
{
	printf("Usage: %s: [-a] [-e] [-b <file>|-f <file>] <var>\n", progname);
}

static void
help(const char *progname)
{
	usage(progname);
	printf("Manipulate the UEFI key database via the efivarfs filesystem\n\n"
	       "Options:\n"
	       "\t-a\tappend a value to the variable instead of replacing it\n"
	       "\t-e\tuse EFI Signature List instead of signed update (only works in Setup Mode\n"
	       "\t-b <binfile>\tAdd hash of <binfile> to the signature list\n"
	       "\t-f <file>\tAdd the key file (.esl or .auth) to the <var>\n"
	       );
}

int
main(int argc, char *argv[])
{
	char *variables[] = { "PK", "KEK", "db", "dbx" };
	EFI_GUID *owners[] = { &GV_GUID, &GV_GUID, &SIG_DB, &SIG_DB };
	EFI_GUID *owner;
	int i, esl_mode = 0, fd, ret;
	struct stat st;
	uint32_t attributes = EFI_VARIABLE_NON_VOLATILE
		| EFI_VARIABLE_RUNTIME_ACCESS
		| EFI_VARIABLE_BOOTSERVICE_ACCESS
		| EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
	char *hash_mode = NULL, *file = NULL, *var, *progname = argv[0], *buf,
		*name;
	

	while (argc > 1 && argv[1][0] == '-') {
		if (strcmp("--version", argv[1]) == 0) {
			version(progname);
			exit(0);
		} else if (strcmp("--help", argv[1]) == 0) {
			help(progname);
			exit(0);
		} else if(strcmp(argv[1], "-a") == 0) {
			attributes |= EFI_VARIABLE_APPEND_WRITE;
			argv += 1;
			argc -= 1;
		} if (strcmp(argv[1], "-e") == 0) {
			esl_mode = 1;
			argv += 1;
			argc -= 1;
		} else if (strcmp(argv[1], "-b") == 0) {
			esl_mode = 1;
			attributes |= EFI_VARIABLE_APPEND_WRITE;
			hash_mode = argv[2];
			argv += 2;
			argc -= 2;
		} else if (strcmp(argv[1], "-f") == 0) {
			file = argv[2];
			argv += 2;
			argc -= 2;
		} else {
			/* unrecognised option */
			break;
		}
	}

	if (argc != 2) {
		usage(progname);
		exit(1);
	}

	var = argv[1];

	for(i = 0; i < ARRAY_SIZE(variables); i++) {
		if (strcmp(var, variables[i]) == 0) {
			owner = owners[i];
			break;
		}
	}
	if (i == ARRAY_SIZE(variables)) {
		fprintf(stderr, "Invalid Variable %s\nVariable must be one of: ", var);
		for (i = 0; i < ARRAY_SIZE(variables); i++)
			fprintf(stderr, "%s ", variables[i]);
		fprintf(stderr, "\n");
		exit(1);
	}

	if (file && hash_mode) {
		fprintf(stderr, "Can only specify one of -f or -b\n");
		exit(1);
	}

	if (!file && !hash_mode) {
		fprintf(stderr, "must specify one of -f or -b\n");
		exit(1);
	}
			
	kernel_variable_init();
	name = file ? file : hash_mode;
	fd = open(name, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Failed to read file %s: ", name);
		perror("");
		exit(1);
	}
	if (fstat(fd, &st) < 0) {
		perror("stat failed");
		exit(1);
	}
	buf = malloc(st.st_size);
	read(fd, buf, st.st_size);
	close(fd);

	if (hash_mode) {
		uint8_t hash[SHA256_DIGEST_SIZE];
		EFI_STATUS status;

		status = sha256_get_pecoff_digest_mem(buf, st.st_size, hash);
		if (status != EFI_SUCCESS) {
			fprintf(stderr, "Failed to get hash of %s\n", name);
			exit(1);
		}
		ret = set_variable_hash(var, owner, attributes, hash);
	} else if (esl_mode) {
		ret = set_variable_esl(var, owner, attributes, st.st_size, buf);
	} else {
		ret = set_variable(var, owner, attributes, st.st_size, buf);
	}

	if (ret == EACCES) {
		fprintf(stderr, "Cannot write to %s, wrong filesystem permissions\n", var);
		exit(1);
	} else if (ret != 0) {
		fprintf(stderr, "Failed to update %s: ", var);
		perror("");
		exit(1);
	}

	return 0;
}
		
