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

#include <sha256.h>
#include <efiauthenticated.h>
#include <guid.h>
#include <version.h>

static void
usage(const char *progname)
{
	printf("Usage: %s efi-binary efi-signature-list\n", progname);
}

static void
help(const char *progname)
{
	usage(progname);
	printf("Produce an EFI Signature List file containing the sha256 hash of the\n"
	       "passed in EFI binary\n"
	       "\nOptions:\n"
	       "none\n"
	       );
}

int
main(int argc, char *argv[])
{
	void *efifile;
	const char *progname = argv[0];
	struct stat st;
	UINT8 hash[SHA256_DIGEST_SIZE];
	int i;

	while (argc > 1) {
		if (strcmp("--version", argv[1]) == 0) {
			version(progname);
			exit(0);
		} else if (strcmp("--help", argv[1]) == 0) {
			help(progname);
			exit(0);
		} else  {
			break;
		}
	}

	if (argc != 3) {
		usage(progname);
		exit(1);
	}

	int fdefifile = open(argv[1], O_RDONLY);
	if (fdefifile == -1) {
		fprintf(stderr, "failed to open file %s: ", argv[1]);
		perror("");
		exit(1);
	}
	fstat(fdefifile, &st);
	efifile = malloc(st.st_size);
	read(fdefifile, efifile, st.st_size);
	close(fdefifile);
	sha256_get_pecoff_digest_mem(efifile, st.st_size, hash);
	printf("HASH IS ");
	for (i = 0; i < SHA256_DIGEST_SIZE; i++) {
		printf("%02x", hash[i]);
	}
	printf("\n");

	UINT8 sig[sizeof(EFI_SIGNATURE_LIST) + sizeof(EFI_SIGNATURE_DATA) - 1 + SHA256_DIGEST_SIZE];
	EFI_SIGNATURE_LIST *l = (void *)sig;
	EFI_SIGNATURE_DATA *d = (void *)sig + sizeof(EFI_SIGNATURE_LIST);

	memset(sig, 0, sizeof(sig));
	l->SignatureType = EFI_CERT_SHA256_GUID;
	l->SignatureListSize = sizeof(sig);
	l->SignatureSize = 16 +32; /* UEFI defined */
	d->SignatureOwner = MOK_OWNER;
	memcpy(&d->SignatureData, hash, sizeof(hash));

	int fdoutfile = open(argv[2], O_CREAT|O_WRONLY|O_TRUNC, S_IWUSR|S_IRUSR);
	if (fdoutfile == -1) {
		fprintf(stderr, "failed to open %s: ", argv[2]);
		perror("");
		exit(1);
	}
	write(fdoutfile, sig, sizeof(sig));
	close(fdoutfile);
	return 0;
}
