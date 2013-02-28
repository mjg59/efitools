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
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>

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
	printf("Usage: %s: [-a] [-e] [-k <key>] [-g <guid>] [-b <file>|-f <file>|-c file] <var>\n", progname);
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
	       "\t-c <file>\tAdd the x509 certificate to the <var> (with <guid> if provided\n"
	       "\t-g <guid>\tOptional <guid> for the X509 Certificate\n"
	       "\t-k <key>\tSecret key file for authorising user mode updates\n"
	       );
}

int
main(int argc, char *argv[])
{
	char *variables[] = { "PK", "KEK", "db", "dbx" };
	char *signedby[] = { "PK", "PK", "KEK", "KEK" };
	EFI_GUID *owners[] = { &GV_GUID, &GV_GUID, &SIG_DB, &SIG_DB };
	EFI_GUID *owner, guid = MOK_OWNER;
	int i, esl_mode = 0, fd, ret;
	struct stat st;
	uint32_t attributes = EFI_VARIABLE_NON_VOLATILE
		| EFI_VARIABLE_RUNTIME_ACCESS
		| EFI_VARIABLE_BOOTSERVICE_ACCESS
		| EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
	char *hash_mode = NULL, *file = NULL, *var, *progname = argv[0], *buf,
		*name, *crt_file = NULL;
	

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
			hash_mode = argv[2];
			argv += 2;
			argc -= 2;
		} else if (strcmp(argv[1], "-f") == 0) {
			file = argv[2];
			argv += 2;
			argc -= 2;
		} else if (strcmp(argv[1], "-g") == 0) {
			if (str_to_guid(argv[2], &guid)) {
				fprintf(stderr, "Invalid GUID %s\n", argv[2]);
				exit(1);
			}
			argv += 2;
			argc -= 2;
		} else if (strcmp(argv[1], "-c") == 0) {
			crt_file = argv[2];
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

	if (!!file + !!hash_mode + !!crt_file != 1) {
		fprintf(stderr, "must specify exactly one of -f, -b or -c\n");
		exit(1);
	}
			
	kernel_variable_init();
	name = file ? file : hash_mode;
	if (name) {
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
	} else if (crt_file) {
		X509 *X = NULL;
		BIO *bio;
		char *crt_file_ext = &crt_file[strlen(crt_file) - 4];

		esl_mode = 1;

		bio = BIO_new_file(crt_file, "r");
		if (!bio) {
			fprintf(stderr, "Failed to load certificate from %s\n", crt_file);
			ERR_print_errors_fp(stderr);
			exit(1);
		}
		if (strcasecmp(crt_file_ext, ".der") == 0
		    || strcasecmp(crt_file_ext, ".cer") == 0)
			/* DER format */
			X = d2i_X509_bio(bio, NULL);
		else
			/* else assume PEM */
			X = PEM_read_bio_X509(bio, NULL, NULL, NULL);
		if (!X) {
			fprintf(stderr, "Failed to load certificate from %s\n", crt_file);
			ERR_print_errors_fp(stderr);
			exit(1);
		}
		BIO_free_all(bio);

		int cert_len = i2d_X509(X, NULL);
		cert_len += sizeof(EFI_SIGNATURE_LIST) + OFFSET_OF(EFI_SIGNATURE_DATA, SignatureData);
		EFI_SIGNATURE_LIST *esl = malloc(cert_len);
		unsigned char *tmp = (unsigned char *)esl + sizeof(EFI_SIGNATURE_LIST) + OFFSET_OF(EFI_SIGNATURE_DATA, SignatureData);
		i2d_X509(X, &tmp);
		esl->SignatureListSize = cert_len;
		esl->SignatureSize = (cert_len - sizeof(EFI_SIGNATURE_LIST));
		esl->SignatureHeaderSize = 0;
		esl->SignatureType = EFI_CERT_X509_GUID;

		EFI_SIGNATURE_DATA *sig_data = (void *)esl + sizeof(EFI_SIGNATURE_LIST);

		sig_data->SignatureOwner = guid;

		buf = (char *)esl;
		st.st_size = cert_len;
	}

	if (hash_mode) {
		uint8_t hash[SHA256_DIGEST_SIZE];
		EFI_STATUS status;
		int len;

		esl_mode = 1;
		attributes |= EFI_VARIABLE_APPEND_WRITE;
		status = sha256_get_pecoff_digest_mem(buf, st.st_size, hash);
		free(buf);
		if (status != EFI_SUCCESS) {
			fprintf(stderr, "Failed to get hash of %s\n", name);
			exit(1);
		}
		buf = (char *)hash_to_esl(&guid, &len, hash);
		st.st_size = len;
		printf("Got hash of size %d\n", st.st_size);
		printf("buf = %02x %02x %02x %02x\n", buf[0], buf[1], buf[2], buf[3]);
	}

	if (esl_mode) {
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
		
