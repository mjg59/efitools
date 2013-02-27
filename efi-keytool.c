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

int
main(int argc, char *argv[])
{
	int setup_mode;

	kernel_variable_init();
	setup_mode = variable_is_setupmode();

	printf("Platform is in %s\n", setup_mode ? "Setup Mode" : "User Mode");
	printf("Secure boot is %s\n", variable_is_secureboot() ? "on" : "off");

	return 0;
}
