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

#define __STDC_VERSION__ 199901L
#include <efi.h>

#include <kernel_efivars.h>
#include <guid.h>

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
		read (fd, buf, st.st_size - sizeof(attr));

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

