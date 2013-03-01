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
	printf("Usage: %s: [-a] [-e] [-d <list>[-<entry>]] [-k <key>] [-g <guid>] [-b <file>|-f <file>|-c file] <var>\n", progname);
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
	       "\t-f <file>\tAdd or Replace the key file (.esl or .auth) to the <var>\n"
	       "\t-c <file>\tAdd or Replace the x509 certificate to the <var> (with <guid> if provided)\n"
	       "\t-g <guid>\tOptional <guid> for the X509 Certificate\n"
	       "\t-k <key>\tSecret key file for authorising User Mode updates\n"
	       "\t-d <list>[-<entry>]\tDelete the signature list <list> (or just a single <entry> within the list)\n"
	       );
}

int
main(int argc, char *argv[])
{
	char *variables[] = { "PK", "KEK", "db", "dbx" };
	char *signedby[] = { "PK", "PK", "KEK", "KEK" };
	EFI_GUID *owners[] = { &GV_GUID, &GV_GUID, &SIG_DB, &SIG_DB };
	EFI_GUID *owner, guid = MOK_OWNER;
	int i, esl_mode = 0, fd, ret, delsig = -1, delentry = -1;
	struct stat st;
	uint32_t attributes = EFI_VARIABLE_NON_VOLATILE
		| EFI_VARIABLE_RUNTIME_ACCESS
		| EFI_VARIABLE_BOOTSERVICE_ACCESS
		| EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
	char *hash_mode = NULL, *file = NULL, *var, *progname = argv[0], *buf,
		*name, *crt_file = NULL, *key_file = NULL;
	

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
		} else if (strcmp(argv[1], "-k") == 0) {
			key_file = argv[2];
			argv += 2;
			argc -= 2;
		} else if (strcmp(argv[1], "-d") == 0) {
			sscanf(argv[2], "%d-%d", &delsig, &delentry);
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

	if (delsig == -1 && (!!file + !!hash_mode + !!crt_file != 1)) {
		fprintf(stderr, "must specify exactly one of -f, -b or -c\n");
		exit(1);
	}
			
	kernel_variable_init();
	ERR_load_crypto_strings();
	OpenSSL_add_all_digests();
	OpenSSL_add_all_ciphers();

	name = file ? file : hash_mode;
	if (delsig != -1) {
		uint32_t len;
		int status = get_variable_alloc(variables[i], owners[i], NULL,
						&len, (uint8_t **)&buf);
		if (status == ENOENT) {
			fprintf(stderr, "Variable %s has no entries\n", variables[i]);
			exit(1);
		}
		EFI_SIGNATURE_LIST  *CertList = (EFI_SIGNATURE_LIST *)buf;
		EFI_SIGNATURE_DATA  *Cert;
		int size, DataSize = len, count = 0;

		certlist_for_each_certentry(CertList, buf, size, DataSize) {
			int Index = 0;

			if (count++ != delsig)
				continue;
			if (delentry == -1)
				goto found;
			certentry_for_each_cert(Cert, CertList) {
				if (Index++ == delentry)
					goto found;
			}
		}
		if (delentry == -1)
			fprintf(stderr, "signature %d does not exist in %s\n", delsig, variables[i]);
		else
			fprintf(stderr, "signature %d-%d does not exist in %s\n", delsig, delentry, variables[i]);
		exit(1);
	found:
		;
		int certs = (CertList->SignatureListSize - sizeof(EFI_SIGNATURE_LIST) - CertList->SignatureHeaderSize) / CertList->SignatureSize;
		if (certs == 1 || delentry == -1) {
			/* delete entire sig list + data */
			DataSize -= CertList->SignatureListSize;
			if (DataSize > 0)
				memcpy(CertList,  (void *) CertList + CertList->SignatureListSize, DataSize - ((char *) CertList - buf));
		} else {
			int remain = DataSize - ((char *)Cert - buf) - CertList->SignatureSize;
			/* only delete single sig */
			DataSize -= CertList->SignatureSize;
			CertList->SignatureListSize -= CertList->SignatureSize;
			if (remain > 0)
				memcpy(Cert, (void *)Cert + CertList->SignatureSize, remain);
		}
		st.st_size = DataSize;	/* reduce length of buf */
		esl_mode = 1;
	} else if (name) {
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
	} else {
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
	}

	if (esl_mode && (!variable_is_setupmode() || strcmp(variables[i], "PK") == 0)) {
		if (!key_file) {
			fprintf(stderr, "Can't update variable%s without a key\n", variable_is_setupmode() ? "" : " in User Mode");
			exit(1);
		}
		BIO *key = BIO_new_file(key_file, "r");
		EVP_PKEY *pkey = PEM_read_bio_PrivateKey(key, NULL, NULL, NULL);
		if (!pkey) {
			fprintf(stderr, "error reading private key %s\n", key_file);
			exit(1);
		}

		uint8_t *esl;
		uint32_t esl_len;
		int ret = get_variable_alloc(signedby[i], &GV_GUID, NULL,
					     &esl_len, &esl);
		if (ret != 0) {
			fprintf(stderr, "Failed to get %s: ", signedby[i]);
			perror("");
			exit(1);
		}
		EFI_SIGNATURE_LIST  *CertList = (EFI_SIGNATURE_LIST *)esl;
		int DataSize = esl_len, size;

		X509 *X = NULL;

		certlist_for_each_certentry(CertList, esl, size, DataSize) {
			EFI_SIGNATURE_DATA  *Cert;
			if (compare_guid(&CertList->SignatureType, &X509_GUID) != 0)
				continue;

			certentry_for_each_cert(Cert, CertList) {
				const unsigned char *psig = (unsigned char *)Cert->SignatureData;
				X = d2i_X509(NULL, &psig, CertList->SignatureSize);
				if (X509_check_private_key(X, pkey))
					goto out;
				X = NULL;
			}
		}
	out:
		if (!X) {
			fprintf(stderr, "No public key matching %s in %s\n", key_file, signedby[i]);
			exit (1);
		}

		EFI_TIME timestamp;
		time_t t;
		struct tm *tm;
		memset(&timestamp, 0, sizeof(timestamp));
		time(&t);
		tm = gmtime(&t);
		/* FIXME: currently timestamp is one year into future because of
		 * the way we set up the secure environment  */
		timestamp.Year = tm->tm_year + 1900 + 1;
		timestamp.Month = tm->tm_mon;
		timestamp.Day = tm->tm_mday;
		timestamp.Hour = tm->tm_hour;
		timestamp.Minute = tm->tm_min;
		timestamp.Second = tm->tm_sec;

		/* signature is over variable name (no null and uc16
		 * chars), the vendor GUID, the attributes, the
		 * timestamp and the contents */
		int signbuflen = strlen(var)*2 + sizeof(EFI_GUID) + sizeof(attributes) + sizeof(timestamp) + st.st_size;
		char *signbuf = malloc(signbuflen);
		char *ptr = signbuf;
		int j;
		for (j = 0; j < strlen(var); j++) {
			*(ptr++) = var[j]; 
			*(ptr++) = 0;
		}
		memcpy(ptr, owners[i], sizeof(*owners[i]));
		ptr += sizeof(*owners[i]);
		memcpy(ptr, &attributes, sizeof(attributes));
		ptr += sizeof(attributes);
		memcpy(ptr, &timestamp, sizeof(timestamp));
		ptr += sizeof(timestamp);
		memcpy(ptr, buf, st.st_size);

		BIO *bio = BIO_new_mem_buf(signbuf, signbuflen);
		PKCS7 *p7 = PKCS7_sign(NULL, NULL, NULL, bio,
				       PKCS7_BINARY | PKCS7_PARTIAL
				       | PKCS7_DETACHED);
		const EVP_MD *md = EVP_get_digestbyname("SHA256");
		PKCS7_sign_add_signer(p7, X, pkey, md, PKCS7_BINARY
				      | PKCS7_DETACHED);
		PKCS7_final(p7, bio, PKCS7_BINARY | PKCS7_DETACHED);


		int sigsize = i2d_PKCS7(p7, NULL);

		EFI_VARIABLE_AUTHENTICATION_2 *var_auth = malloc(sizeof(EFI_VARIABLE_AUTHENTICATION_2) + sigsize);
		var_auth->TimeStamp = timestamp;
		var_auth->AuthInfo.CertType = EFI_CERT_TYPE_PKCS7_GUID;
		var_auth->AuthInfo.Hdr.dwLength = sigsize + OFFSET_OF(WIN_CERTIFICATE_UEFI_GUID, CertData);
		var_auth->AuthInfo.Hdr.wRevision = 0x0200;
		var_auth->AuthInfo.Hdr.wCertificateType = WIN_CERT_TYPE_EFI_GUID;
		unsigned char *tmp = var_auth->AuthInfo.CertData;
		i2d_PKCS7(p7, &tmp);
		ERR_print_errors_fp(stderr);

		/* new update now consists of two parts: the
		 * authentication header with the signature and the
		 * payload (the original esl) */
		int siglen = OFFSET_OF(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo.CertData) + sigsize;
		char *newbuf = malloc(siglen + st.st_size);

		memcpy(newbuf, var_auth, siglen);
		memcpy(newbuf + siglen, buf, st.st_size);

		free(buf);
		free(esl);
		free(var_auth);
		buf = newbuf;
		st.st_size = siglen + st.st_size;
		esl_mode = 0;
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
		
