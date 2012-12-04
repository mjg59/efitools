/*
 * Copyright 2012 <James.Bottomley@HansenPartnership.com>
 *
 * see COPYING file
 */


#include <stdint.h>
#define __STDC_VERSION__ 199901L
#include <efi.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/pem.h>
#include <openssl/err.h>

#include <variables.h>
#include <version.h>

static void
usage(const char *progname)
{
	printf("Usage: %s [-g <guid>] [-r] <crt file> <efi sig list file>\n", progname);
}

static void
help(const char * progname)
{
	usage(progname);
	printf("Take an input certificate (in PEM format) and convert it to an EFI\n"
	       "signature list file containing only that single certificate\n\n"
	       "Options:\n"
	       "\t-r               The file contains an RSA2048 certificate instead of the\n"
	       "\t                 Default X509 format [UNIMPLEMENTED]\n"
	       "\t-g <guid>        Use <guid> as the owner of the signature. If this is not\n"
	       "\t                 supplied, an all zero guid will be used\n"

	       );
	
}

int
main(int argc, char *argv[])
{
	char *certfile, *efifile;
	const char *progname = argv[0];
	int rsasig;
	EFI_GUID owner = { 0 };

	while (argc > 1) {
		if (strcmp("--version", argv[1]) == 0) {
			version(progname);
			exit(0);
		} else if (strcmp("--help", argv[1]) == 0) {
			help(progname);
			exit(0);
		} else if (strcmp("-g", argv[1]) == 0) {
			str_to_guid(argv[2], &owner);
			argv += 2;
			argc -= 2;
		} else if (strcmp("-r", argv[1]) == 0) {
			rsasig = 1;
			argv += 1;
			argc += 1;
		} else {
			break;
		}
	}
	  

	if (argc != 3) {

		exit(1);
	}

	certfile = argv[1];
	efifile = argv[2];

        ERR_load_crypto_strings();
        OpenSSL_add_all_digests();
        OpenSSL_add_all_ciphers();

        BIO *cert_bio = BIO_new_file(certfile, "r");
        X509 *cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
	int PkCertLen = i2d_X509(cert, NULL);

	PkCertLen += sizeof(EFI_SIGNATURE_LIST) + OFFSET_OF(EFI_SIGNATURE_DATA, SignatureData);
	EFI_SIGNATURE_LIST          *PkCert = malloc (PkCertLen);
	if (!PkCert) {
		fprintf(stderr, "failed to malloc cert\n");
		exit(1);
	}
	unsigned char *tmp = (unsigned char *)PkCert + sizeof(EFI_SIGNATURE_LIST) + OFFSET_OF(EFI_SIGNATURE_DATA, SignatureData);
	i2d_X509(cert, &tmp);
	PkCert->SignatureListSize   = PkCertLen;
	PkCert->SignatureSize       = (UINT32) (PkCertLen - sizeof(EFI_SIGNATURE_LIST));
	PkCert->SignatureHeaderSize = 0;
	PkCert->SignatureType = EFI_CERT_X509_GUID;

	EFI_SIGNATURE_DATA *PkCertData = (void *)PkCert + sizeof(EFI_SIGNATURE_LIST);

	PkCertData->SignatureOwner = owner; 

	FILE *f = fopen(efifile, "w");
	if (!f) {
		fprintf(stderr, "failed to open efi file %s: ", efifile);
		perror("");
		exit(1);
	}
	if (fwrite(PkCert, 1, PkCertLen, f) != PkCertLen) {
		perror("Did not write enough bytes to efi file");
		exit(1);
	}


	return 0;
}
