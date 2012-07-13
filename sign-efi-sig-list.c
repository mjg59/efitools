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

#include <variables.h>

int
main(int argc, char *argv[])
{
	char *certfile, *efifile, *keyfile, *outfile, *str;
	const char *progname = argv[0];
	int rsasig = 0, monotonic = 0, varlen, i;
	EFI_GUID vendor_guid;
	struct stat st;
	wchar_t var[256];
	UINT32 attributes = EFI_VARIABLE_NON_VOLATILE
		| EFI_VARIABLE_RUNTIME_ACCESS
		| EFI_VARIABLE_BOOTSERVICE_ACCESS
		| EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
	EFI_TIME timestamp;

	while (argc > 1) {
		if (strcmp("-g", argv[1]) == 0) {
			sscanf(argv[2],
			       "%8x-%4hx-%4hx-%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx",
			       &vendor_guid.Data1, &vendor_guid.Data2, &vendor_guid.Data3,
			       vendor_guid.Data4, vendor_guid.Data4 + 1, vendor_guid.Data4 + 2,
			       vendor_guid.Data4 + 3, vendor_guid.Data4 + 4, vendor_guid.Data4 + 5,
			       vendor_guid.Data4 + 6, vendor_guid.Data4 + 7);
			argv += 2;
			argc -= 2;
		} else if (strcmp("-r", argv[1]) == 0) {
			rsasig = 1;
			argv += 1;
			argc -= 1;
		} else if (strcmp("-c", argv[1]) == 0)  {
			monotonic = 1;
			argv += 1;
			argc -= 1;
			attributes &= ~EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
			attributes |= EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS;

		} else if (strcmp("-a", argv[1]) == 0) {
			attributes |= EFI_VARIABLE_APPEND_WRITE;
		} else  {
			break;
		}
	}

	if (argc != 6) {
		fprintf(stderr, "Usage: %s [-r] [-c] [-a] [-g guid] <var> <crt file> <key file> <efi sig list file> <output auth file>\n", progname);
		exit(1);
	}

	if (rsasig || monotonic) {
		/* FIXME: need to do rsa signatures and monotonic payloads */
		exit(1);
	}

	str = argv[1];
	certfile = argv[2];
	keyfile = argv[3];
	efifile = argv[4];
	outfile = argv[5];

	/* Specific GUIDs for special variables */
	if (strcmp(str, "PK") == 0 || strcmp(str, "KEK") == 0) {
		vendor_guid = (EFI_GUID)EFI_GLOBAL_VARIABLE;
	} else if (strcmp(str, "db") == 0 || strcmp(str, "dbx") == 0) {
		vendor_guid = (EFI_GUID){ 0xd719b2cb, 0x3d3a, 0x4596, {0xa3, 0xbc, 0xda, 0xd0,  0xe, 0x67, 0x65, 0x6f }};
	}

	memset(&timestamp, 0, sizeof(timestamp));
	time_t t;
	time(&t);
	struct tm *tm = gmtime(&t);

	timestamp.Year = tm->tm_year + 1900;
	timestamp.Month = tm->tm_mon;
	timestamp.Day = tm->tm_mday;
	timestamp.Hour = tm->tm_hour;
	timestamp.Minute = tm->tm_min;
	timestamp.Second = tm->tm_sec;

	/* Warning: don't use any glibc wchar functions.  We're building
	 * with -fshort-wchar which breaks the glibc ABI */
	i = 0;
	do {
		var[i] = str[i];
	} while (str[i++] != '\0');

	varlen = (i - 1)*sizeof(wchar_t);


        ERR_load_crypto_strings();
        OpenSSL_add_all_digests();
        OpenSSL_add_all_ciphers();

        BIO *cert_bio = BIO_new_file(certfile, "r");
        X509 *cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
	if (!cert) {
		fprintf(stderr, "error reading certificate %s\n", certfile);
		exit(1);
	}

	BIO *privkey_bio = BIO_new_file(keyfile, "r");
	EVP_PKEY *pkey = PEM_read_bio_PrivateKey(privkey_bio, NULL, NULL, NULL);
	if (!pkey) {
		fprintf(stderr, "error reading private key %s\n", keyfile);
		exit(1);
	}

	int fdefifile = open(efifile, O_RDONLY);
	if (fdefifile == -1) {
		fprintf(stderr, "failed to open file %s: ", efifile);
		perror("");
		exit(1);
	}
	fstat(fdefifile, &st);

	/* signature is over variable name (no null), the vendor GUID, the
	 * attributes, the timestamp and the contents */
	int signbuflen = varlen + sizeof(EFI_GUID) + sizeof(UINT32) + sizeof(EFI_TIME) + st.st_size;
	char *signbuf = malloc(signbuflen);
	char *ptr = signbuf;
	memcpy(ptr, var, varlen);
	ptr += varlen;
	memcpy(ptr, &vendor_guid, sizeof(vendor_guid));
	ptr += sizeof(vendor_guid);
	memcpy(ptr, &attributes, sizeof(attributes));
	ptr += sizeof(attributes);
	memcpy(ptr, &timestamp, sizeof(timestamp));
	ptr += sizeof(timestamp);
	read(fdefifile, ptr, st.st_size);

	
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx,signbuf, signbuflen);
	uint8_t digest[SHA256_DIGEST_LENGTH];
	SHA256_Final(digest, &ctx);

	BIO *bio_data = BIO_new_mem_buf(digest, sizeof(digest));
	
	PKCS7 *p7 = PKCS7_sign(cert, pkey, NULL, bio_data, PKCS7_BINARY);

	int sigsize = i2d_PKCS7(p7, NULL);

	EFI_VARIABLE_AUTHENTICATION_2 *var_auth = malloc(sizeof(EFI_VARIABLE_AUTHENTICATION_2) + sigsize - 1);
	unsigned char *sigbuf = var_auth->AuthInfo.CertData;

	var_auth->TimeStamp = timestamp;
	var_auth->AuthInfo.CertType = EFI_CERT_TYPE_PKCS7_GUID;
	var_auth->AuthInfo.Hdr.dwLength = sigsize + sizeof(WIN_CERTIFICATE_UEFI_GUID) - 1;
	var_auth->AuthInfo.Hdr.wRevision = 0x0200;
	var_auth->AuthInfo.Hdr.wCertificateType = WIN_CERT_TYPE_EFI_GUID;

	i2d_PKCS7(p7, &sigbuf);
	ERR_print_errors_fp(stdout);

	int fdoutfile = open(outfile, O_CREAT|O_WRONLY, S_IWUSR|S_IRUSR);
	if (fdoutfile == -1) {
		fprintf(stderr, "failed to open %s: ", outfile);
		perror("");
		exit(1);
	}
	write(fdoutfile, var_auth, sizeof(EFI_VARIABLE_AUTHENTICATION_2) + sigsize - 1);
	close(fdoutfile);

	return 0;
}
