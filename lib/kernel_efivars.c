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
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#define __STDC_VERSION__ 199901L
#include <efi.h>

#include <kernel_efivars.h>
#include <guid.h>
#include <sha256.h>
#include "efiauthenticated.h"

static char *kernel_efi_path = NULL;

void
kernel_variable_init(void)
{
	char fname[] = "/tmp/efi.XXXXXX";
	char cmdline[256];
	int fd, ret;
	struct stat st;
	char *buf;

	if (kernel_efi_path)
		return;
	mktemp(fname);
	snprintf(cmdline, sizeof(cmdline), "mount -l > %s", fname);
	ret = system(cmdline);
	if (WEXITSTATUS(ret) != 0)
		/* hopefully stderr said what was wrong */
		exit(1);
	fd = open(fname, O_RDONLY);
	unlink(fname);
	if (fd < 0) {
		fprintf(stderr, "Failed to open output of %s\n", cmdline);
		exit(1);
	}
	if (fstat(fd, &st) < 0) {
		perror("stat failed");
		exit(1);
	}
	if (st.st_size == 0) {
		fprintf(stderr, "No efivarfs filesystem is mounted\n");
		exit(1);
	}
	buf = malloc(st.st_size);
	read(fd, buf, st.st_size);
	close(fd);

	char *ptr = buf;
	char path[512], type[512];
	while (ptr < buf + st.st_size) {
		int count;

		sscanf(ptr, "%*s on %s type %s %*s\n%n", path, type, &count);
		ptr += count;
		if (strcmp(type, "efivarfs") != 0)
			continue;
	}
	if (strcmp(type, "efivarfs") != 0) {
		fprintf(stderr, "No efivarfs filesystem is mounted\n");
		exit(1);
	}
	kernel_efi_path = malloc(strlen(path) + 1);
	strcpy(kernel_efi_path, path);
}

int
get_variable(const char *var, EFI_GUID *guid, uint32_t *attributes,
	     uint32_t *size, void *buf)
{
	if (!kernel_efi_path)
		return -EINVAL;

	int varfs_len = strlen(var) + 48 + strlen(kernel_efi_path);
	char *varfs = malloc(varfs_len);
	uint32_t attr;
	int fd;
	struct stat st;

	snprintf(varfs, varfs_len, "%s/%s-%s", kernel_efi_path,
		 var, guid_to_str(guid));
	fd = open(varfs, O_RDONLY);
	free(varfs);
	if (fd < 0)
		return errno;
	
	if (fstat(fd, &st) < 0)
		return errno;
	if (size)
		*size = st.st_size - sizeof(attr);

	read(fd, &attr, sizeof(attr));

	if (attributes)
		*attributes = attr;

	if (buf)
		read(fd, buf, st.st_size - sizeof(attr));

	close(fd);

	return 0;
}

int
get_variable_alloc(const char *var, EFI_GUID *guid, uint32_t *attributes,
		   uint32_t *size, uint8_t **buf)
{
	uint32_t len;
	int ret = get_variable(var, guid, NULL, &len, NULL);
	if (ret)
		return ret;

	*buf = malloc(len);
	if (!buf)
		return -ENOMEM;

	return get_variable(var, guid, attributes, size, *buf);
}

int
variable_is_setupmode(void)
{
	uint8_t setup_mode;

	get_variable("SetupMode", &GV_GUID, NULL, NULL, &setup_mode);

	return setup_mode;
}

int
variable_is_secureboot(void)
{
	uint8_t secure_boot;

	get_variable("SecureBoot", &GV_GUID, NULL, NULL, &secure_boot);

	return secure_boot;
}

int
set_variable(const char *var, EFI_GUID *guid, uint32_t attributes,
	     uint32_t size, void *buf)
{
	if (!kernel_efi_path)
		return -EINVAL;

	int varfs_len = strlen(var) + 48 + strlen(kernel_efi_path);
	char *varfs = malloc(varfs_len),
		*newbuf = malloc(size + sizeof(attributes));
	int fd;

	snprintf(varfs, varfs_len, "%s/%s-%s", kernel_efi_path,
		 var, guid_to_str(guid));
	fd = open(varfs, O_RDWR|O_CREAT|O_TRUNC, 0644);
	free(varfs);
	if (fd < 0)
		return errno;
	memcpy(newbuf, &attributes, sizeof(attributes));
	memcpy(newbuf + sizeof(attributes), buf, size);
	
	if (write(fd, newbuf, size + sizeof(attributes)) != size + sizeof(attributes))
		return errno;

	close(fd);

	return 0;
}
int
set_variable_esl(const char *var, EFI_GUID *guid, uint32_t attributes,
		 uint32_t size, void *buf)
{
	if (!kernel_efi_path)
		return -EINVAL;

	int newsize = size + OFFSET_OF(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo) + OFFSET_OF(WIN_CERTIFICATE_UEFI_GUID, CertData);
	char *newdata = malloc(newsize);
	EFI_VARIABLE_AUTHENTICATION_2 *DescriptorData;
	EFI_TIME *Time;
	struct tm tm;
	time_t t;

	time(&t);

	memset(newdata, '\0', newsize);
	memcpy(newdata + newsize - size, buf, size);
	DescriptorData = (EFI_VARIABLE_AUTHENTICATION_2 *)newdata;
	Time = &DescriptorData->TimeStamp;
	gmtime_r(&t, &tm);
	/* FIXME: currently timestamp is one year into future because of
	 * the way we set up the secure environment  */
	Time->Year = tm.tm_year + 1900 + 1;
	Time->Month = tm.tm_mon;
	Time->Day = tm.tm_mday;
	Time->Hour = tm.tm_hour;
	Time->Minute = tm.tm_min;
	Time->Second = tm.tm_sec;
	DescriptorData->AuthInfo.Hdr.dwLength  = OFFSET_OF (WIN_CERTIFICATE_UEFI_GUID, CertData);
	DescriptorData->AuthInfo.Hdr.wRevision = 0x0200;
	DescriptorData->AuthInfo.Hdr.wCertificateType = WIN_CERT_TYPE_EFI_GUID;
	DescriptorData->AuthInfo.CertType =  EFI_CERT_TYPE_PKCS7_GUID;

	int ret = set_variable(var, guid, attributes, newsize, newdata);
	free(newdata);
	return ret;
}

uint8_t *
hash_to_esl(EFI_GUID *owner, int *len,
	    uint8_t hash[SHA256_DIGEST_SIZE])
{
	const int siglen = sizeof(EFI_SIGNATURE_LIST) + sizeof(EFI_SIGNATURE_DATA) - 1 + SHA256_DIGEST_SIZE;
	uint8_t *sig = malloc(siglen);
	EFI_SIGNATURE_LIST *l = (void *)sig;
	EFI_SIGNATURE_DATA *d = (void *)sig + sizeof(EFI_SIGNATURE_LIST);

	if (len)
		*len = siglen;

	memset(sig, 0, siglen);
	l->SignatureType = EFI_CERT_SHA256_GUID;
	l->SignatureListSize = siglen;
	l->SignatureSize = 16 +32; /* UEFI defined */
	memcpy(&d->SignatureData, hash, SHA256_DIGEST_SIZE);
	d->SignatureOwner = *owner;

	return sig;
}

int
set_variable_hash(const char *var, EFI_GUID *owner, uint32_t attributes,
		  uint8_t hash[SHA256_DIGEST_SIZE])
{
	int len;
	uint8_t *sig = hash_to_esl(&MOK_OWNER, &len, hash);

	int ret = set_variable_esl(var, owner, attributes, len, sig);
	free(sig);
	return ret;
}
