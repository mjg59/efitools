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
	printf("Usage: %s: [-v <var>] [-s <list>[-<entry>]] [-o <file>]\n", progname);
}

static void
help(const char *progname)
{
	usage(progname);
	printf("List the contents of the UEFI signature databases\n\n"
	       "Options:\n"
	       "\t-v <var>\tlist only the contents of <var>\n"
	       "\t-s <list>[-<entry>]\tlist only a given signature list (and optionally\n"
	       "\t\tonly a given entry in that list\n"
	       "\t-o <file>\toutput the requested signature lists to <file>\n"
	       );
}

void
parse_db(const char *name, uint8_t *data, uint32_t len, int sig, int entry)
{
	EFI_SIGNATURE_LIST  *CertList = (EFI_SIGNATURE_LIST *)data;
	EFI_SIGNATURE_DATA  *Cert;
	long count = 0, DataSize = len;
	int size;

	certlist_for_each_certentry(CertList, data, size, DataSize) {
		int Index = 0;
		const char *ext;

		if (sig != -1 && count != sig)
			continue;


		if (compare_guid(&CertList->SignatureType, &X509_GUID)== 0) {
			ext = "X509";
		} else if (compare_guid(&CertList->SignatureType, &RSA2048_GUID) == 0) {
			ext = "RSA2048";
		} else if (compare_guid(&CertList->SignatureType, &PKCS7_GUID) == 0) {
			ext = "PKCS7";
		} else if (compare_guid(&CertList->SignatureType, &EFI_CERT_SHA256_GUID) == 0) {
			ext = "SHA256";
		} else {
			ext = "Unknown";
		}

		printf("%s: List %ld, type %s\n", name, count++, ext);

		certentry_for_each_cert(Cert, CertList) {
			if (entry != -1 && Index != entry)
				continue;

			printf("    Signature %d, size %d, owner %s\n",
			      Index++, CertList->SignatureSize,
			      guid_to_str(&Cert->SignatureOwner));

			if (strcmp(ext, "X509") == 0) {
				const unsigned char *buf = (unsigned char *)Cert->SignatureData;
				X509 *X = d2i_X509(NULL, &buf,
						   CertList->SignatureSize);
				X509_NAME *issuer = X509_get_issuer_name(X);
				X509_NAME *subject = X509_get_subject_name(X);
				
				printf("        Subject:\n");
				X509_NAME_print_ex_fp(stdout, subject, 12, XN_FLAG_SEP_CPLUS_SPC);
				printf("\n        Issuer:\n");
				X509_NAME_print_ex_fp(stdout, issuer, 12, XN_FLAG_SEP_CPLUS_SPC);
				printf("\n");

			} else if (strcmp(ext, "SHA256") == 0) {
				uint8_t *hash = Cert->SignatureData;
				int j;

				printf("        Hash:");
				for (j = 0; j < SHA256_DIGEST_SIZE; j++) {
					printf("%02x", hash[j]);
				}
				printf("\n");
			}
		}
	}
}

int
main(int argc, char *argv[])
{
  char *variables[] = { "PK", "KEK", "db", "dbx" , "MokList" };
	char *progname = argv[0], *var = NULL, *file = NULL;
	EFI_GUID *owners[] = { &GV_GUID, &GV_GUID, &SIG_DB, &SIG_DB, &MOK_OWNER };
	int i, found = 0, sig = -1, entry = -1, fd;

	while (argc > 1 && argv[1][0] == '-') {
		if (strcmp("--version", argv[1]) == 0) {
			version(progname);
			exit(0);
		} else if (strcmp("--help", argv[1]) == 0) {
			help(progname);
			exit(0);
		} else if(strcmp(argv[1], "-v") == 0) {
			var = argv[2];
			argv += 2;
			argc -= 2;
		} else if (strcmp(argv[1], "-s") == 0) {
			sscanf(argv[2], "%d-%d", &sig, &entry);
			argv += 2;
			argc -= 2;
		} else if (strcmp(argv[1], "-o") == 0) {
			file = argv[2];
			argv += 2;
			argc -= 2;
		} else {
			/* unrecognised option */
			break;
		}
	}

	if (argc != 1) {
		usage(progname);
		exit(1);
	}

	if (sig != -1 && !var) {
		fprintf(stderr, "need -v <var> with -s option\n");
		exit(1);
	}

	if (file) {
		fd = open(file, O_CREAT|O_TRUNC|O_WRONLY, 0600);
		if (fd < 0) {
			fprintf(stderr, "failed to open %s: ", file);
			perror("");
			exit(1);
		}
	}

	kernel_variable_init();
	for (i = 0; i < ARRAY_SIZE(owners); i++) {
		int status;
		uint32_t len;
		uint8_t *buf;

		if (var && strcmp(var, variables[i]) != 0)
			continue;

		found = 1;
		status = get_variable_alloc(variables[i], owners[i], NULL,
					    &len, &buf);
		if (status == ENOENT) {
			printf("Variable %s has no entries\n", variables[i]);
			continue;
		} else if (status != 0) {
			printf("Failed to get %s: %d\n", variables[i], status);
			continue;
		}
		printf("Variable %s, length %d\n", variables[i], len);
		if (file)
			write(fd, buf, len);
		else
			parse_db(variables[i], buf, len, sig, entry);
		free(buf);
	}
	if (file)
		close(fd);
	if (!found) {
		fprintf(stderr, "variable %s is not a UEFI secure boot variable\n", var);
		exit(1);
	}
	return 0;
}
		
