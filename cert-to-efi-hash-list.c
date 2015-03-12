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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <wchar.h>

#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#include <guid.h>
#include <variables.h>
#include <version.h>

static void
usage(const char *progname)
{
	printf("Usage: %s [-g <guid>][-t <timestamp>][-s <hash>] <crt file> <efi sig list file>\n", progname);
}

static void
help(const char * progname)
{
	usage(progname);
	printf("Take an input X509 certificate (in PEM format) and convert it to an EFI\n"
	       "signature hash list file containing only that single certificate\n\n"
	       "Options:\n"
	       "\t-g <guid>        Use <guid> as the owner of the signature. If this is not\n"
	       "\t                 supplied, an all zero guid will be used\n"
	       "\t-s <hash>        Use SHA<hash> hash algorithm (256, 384, 512)\n"
	       "\t-t <timestamp>   Time of Revocation for hash signature\n"
	       "                   Set to 0 if not specified meaning revoke\n"
	       "                   for all time.\n"
	       );
	
}

int
main(int argc, char *argv[])
{
	char *certfile, *efifile;
	const char *progname = argv[0];
	EFI_GUID owner = { 0 };
	int sha = 256;
	EFI_TIME timestamp;
	char *timestampstr = NULL;

	memset(&timestamp, 0, sizeof(timestamp));

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
		} else if (strcmp("-s", argv[1]) == 0) {
			sha = atoi(argv[2]);
			argv += 2;
			argc -= 2;
		} else if (strcmp("-t", argv[1]) == 0) {
			timestampstr = argv[2];
			argv += 2;
			argc -= 2;
		} else {
			break;
		}
	}
	  

	if (argc != 3) {
		usage(progname);
		exit(1);
	}

	if (sha != 256 && sha != 384 && sha != 512) {
		fprintf(stderr, "Supported algorithms are sha256, sha384 or sha512\n");
		exit(1);
	}

	if (timestampstr) {
		struct tm tms;
		strptime(timestampstr, "%Y-%m-%d %H:%M:%S", &tms);
		/* timestamp.Year is from 0 not 1900 as tm year is */
		tms.tm_year += 1900;
		timestamp.Year = tms.tm_year;
		timestamp.Month = tms.tm_mon + 1;
		timestamp.Day = tms.tm_mday;
		timestamp.Hour = tms.tm_hour;
		timestamp.Minute = tms.tm_min;
		timestamp.Second = tms.tm_sec;
	}
	certfile = argv[1];
	efifile = argv[2];

	printf("TimeOfRevocation is %d-%d-%d %02d:%02d:%02d\n", timestamp.Year,
	       timestamp.Month, timestamp.Day, timestamp.Hour, timestamp.Minute,
	       timestamp.Second);

        ERR_load_crypto_strings();
        OpenSSL_add_all_digests();
        OpenSSL_add_all_ciphers();
	/* here we may get highly unlikely failures or we'll get a
	 * complaint about FIPS signatures (usually becuase the FIPS
	 * module isn't present).  In either case ignore the errors
	 * (malloc will cause other failures out lower down */
	ERR_clear_error();

        BIO *cert_bio = BIO_new_file(certfile, "r");
        X509 *cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
	unsigned char *cert_buf = NULL;

	int cert_len = i2d_X509_CINF(cert->cert_info, &cert_buf);
	ERR_print_errors_fp(stdout);

	int len, digest_len, time_offset;
	EFI_GUID guid;
	const EVP_MD *md;

	if (sha == 256) {
		len = sizeof(EFI_CERT_X509_SHA256);
		digest_len = sizeof(EFI_SHA256_HASH);
		guid = EFI_CERT_X509_SHA256_GUID;
		md = EVP_get_digestbyname("SHA256");
		time_offset = OFFSET_OF(EFI_CERT_X509_SHA256, TimeOfRevocation);
	} else if (sha == 384) {
		len = sizeof(EFI_CERT_X509_SHA384);
		digest_len = sizeof(EFI_SHA384_HASH);
		guid = EFI_CERT_X509_SHA384_GUID;
		md = EVP_get_digestbyname("SHA384");
		time_offset = OFFSET_OF(EFI_CERT_X509_SHA384, TimeOfRevocation);
	} else if (sha == 512) {
		len = sizeof(EFI_CERT_X509_SHA512);
		digest_len = sizeof(EFI_SHA512_HASH);
		guid = EFI_CERT_X509_SHA512_GUID;
		md = EVP_get_digestbyname("SHA512");
		time_offset = OFFSET_OF(EFI_CERT_X509_SHA512, TimeOfRevocation);
	} else {
		fprintf(stderr, "assertion failure sha%d\n", sha);
		exit(1);
	}
	len += sizeof(EFI_SIGNATURE_LIST) + OFFSET_OF(EFI_SIGNATURE_DATA, SignatureData);
	unsigned char *buf = malloc(len);
	EFI_SIGNATURE_LIST *SigList = (EFI_SIGNATURE_LIST *)buf;
	SigList->SignatureListSize = len;
	SigList->SignatureSize = (UINT32)(len - sizeof(EFI_SIGNATURE_LIST));
	SigList->SignatureHeaderSize = 0;
	SigList->SignatureType = guid;

	EFI_SIGNATURE_DATA *SigData = (void *)buf + sizeof(EFI_SIGNATURE_LIST);
	SigData->SignatureOwner = owner;

	/* point buf at hash buffer */
	unsigned char *digest = (void *)SigData + OFFSET_OF(EFI_SIGNATURE_DATA, SignatureData);

	EFI_TIME *TimeOfRevocation = (void *)digest + time_offset;
	*TimeOfRevocation = timestamp;

	EVP_MD_CTX *ctx;
	unsigned int md_len;
	ctx = EVP_MD_CTX_create();
        EVP_DigestInit_ex(ctx, md, NULL);
        EVP_DigestUpdate(ctx, cert_buf, cert_len);
        EVP_DigestFinal_ex(ctx, digest, &md_len);
        EVP_MD_CTX_destroy(ctx);
	if (digest_len != md_len) {
		fprintf(stderr, "Digest assertion failure sha%d %d != %d\n",
			sha, digest_len, md_len);
		exit(1);
	}

	FILE *f = fopen(efifile, "w");
	if (!f) {
		fprintf(stderr, "failed to open efi file %s: ", efifile);
		perror("");
		exit(1);
	}
	if (fwrite(buf, 1, len, f) != len) {
		perror("Did not write enough bytes to efi file");
		exit(1);
	}

	return 0;
}
