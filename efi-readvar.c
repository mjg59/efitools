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
#include "efiauthenticated.h"

#define ARRAY_SIZE(a) (sizeof (a) / sizeof ((a)[0]))

void
parse_db(const char *name, uint8_t *data, uint32_t len)
{
	EFI_SIGNATURE_LIST  *CertList = (EFI_SIGNATURE_LIST *)data;
	EFI_SIGNATURE_DATA  *Cert;
	long count = 0, DataSize = len;
	int size;

	certlist_for_each_certentry(CertList, data, size, DataSize) {
		int Index = 0;
		const char *ext;
		count++;

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

		printf("%s: List %ld, type %s\n", name, count, ext);

		certentry_for_each_cert(Cert, CertList) {
			printf("    Signature %d, size %d, owner %s\n",
			      Index++, CertList->SignatureSize,
			      guid_to_str(&Cert->SignatureOwner));

			if (strcmp(ext, "X509") == 0) {
				void *buf = Cert->SignatureData;
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
	char *variables[] = { "PK", "KEK", "db", "dbx" };
	EFI_GUID *owners[] = { &GV_GUID, &GV_GUID, &SIG_DB, &SIG_DB };
	int i;

	kernel_variable_init();
	for (i = 0; i < ARRAY_SIZE(owners); i++) {
		int status;
		uint32_t len;
		uint8_t *buf;

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
		parse_db(variables[i], buf, len);
		free(buf);
	}
	return 0;
}
		
