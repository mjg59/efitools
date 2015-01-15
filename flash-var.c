#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

#define __STDC_VERSION__ 199901L
#include <efi.h>

#include <version.h>
#include <guid.h>
#include "efiauthenticated.h"
#include "variableformat.h"

static void
usage(const char *progname)
{
	printf("Usage: %s: [-l] [-g <owner guid>] [-t <timestamp>] <flashfile> <var> <varcontentfile>\n", progname);
}

static void
help(const char *progname)
{
	usage(progname);
	printf("Poke a variable definition into a flash file\n\n"
	       "Options:\n"
	       "\t-g <owner guid>      Variable owner GUID\n"
	       "\t-t <timestamp>       Timestamp for the authenticated variable\n"
	       "\t-l                    List current flash variables\n"
	       );
}

int
main(int argc, char *argv[])
{
	char *progname = argv[0], *buf, *vardata, *timestampstr = NULL;
	uint32_t attributes = EFI_VARIABLE_NON_VOLATILE
		| EFI_VARIABLE_RUNTIME_ACCESS
		| EFI_VARIABLE_BOOTSERVICE_ACCESS
		| EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
	int flashfile, varfile, i, offset, varlen, varfilesize, listvars = 0;
	const int chunk = 8;
	wchar_t var[128];
	struct stat st;
	EFI_GUID *owner = NULL, guid;
	EFI_TIME timestamp;

	while (argc > 1 && argv[1][0] == '-') {
		if (strcmp("--version", argv[1]) == 0) {
			version(progname);
			exit(0);
		} else if (strcmp("--help", argv[1]) == 0) {
			help(progname);
			exit(0);
		} else if (strcmp(argv[1], "-g") == 0) {
			if (str_to_guid(argv[2], &guid)) {
				fprintf(stderr, "Invalid GUID %s\n", argv[2]);
				exit(1);
			}
			owner = &guid;
			argv += 2;
			argc -= 2;
		} else if (strcmp("-t", argv[1]) == 0) {
			timestampstr = argv[2];
			argv += 2;
			argc -= 2;
		} else if (strcmp("-l", argv[1]) == 0) {
			listvars = 1;
			argv += 1;
			argc -= 1;
		} else {
			/* unrecognised option */
			break;
		}
	}

	if ((argc != 4 && !listvars) || (argc != 2 && listvars)) {
		usage(progname);
		exit(1);
	}

	/* copy to wchar16_t including trailing zero */
	for (i = 0; i < strlen(argv[2]) + 1; i++)
		var[i] = argv[2][i];
	varlen = i*2;		/* size of storage including zero */

	if (!owner)
		owner = get_owner_guid(argv[2]);
	if (!owner) {
		fprintf(stderr, "variable %s has no defined guid, one must be specified\n", argv[2]);
		exit(1);
	}


	memset(&timestamp, 0, sizeof(timestamp));
	time_t t;
	struct tm *tm, tms;

	memset(&tms, 0, sizeof(tms));


	if (timestampstr) {
		strptime(timestampstr, "%Y-%m-%d %H:%M:%S", &tms);
		tm = &tms;
	} else {
		time(&t);
		tm = localtime(&t);
	}

	/* timestamp.Year is from 0 not 1900 as tm year is */
	timestamp.Year = tm->tm_year + 1900;
	/* timestamp Month is 1-12 not 0-11 as tm_mon is */
	timestamp.Month = tm->tm_mon + 1;
	timestamp.Day = tm->tm_mday;
	timestamp.Hour = tm->tm_hour;
	timestamp.Minute = tm->tm_min;
	timestamp.Second = tm->tm_sec;

	printf("Timestamp is %d-%d-%d %02d:%02d:%02d\n", timestamp.Year,
	       timestamp.Month, timestamp.Day, timestamp.Hour, timestamp.Minute,
	       timestamp.Second);

	flashfile = open(argv[1], O_RDWR);
	if (flashfile < 0) {
		fprintf(stderr, "Failed to read file %s:", argv[1]);
		perror("");
	}

	varfile = open(argv[3], O_RDONLY);
	if (varfile < 0) {
		fprintf(stderr, "Failed to read file %s:", argv[1]);
		perror("");
	}
	fstat(varfile, &st);
	varfilesize = st.st_size;

	vardata = malloc(varfilesize);
	if (read(varfile, vardata, varfilesize) != varfilesize) {
		perror("Failed to read variable file");
		exit(1);
	}
	close(varfile);

	buf = malloc(sizeof(EFI_GUID));

	for (i = 0; ; i += chunk) {
		lseek(flashfile, i, SEEK_SET);
		if (read(flashfile, buf, sizeof(EFI_GUID)) != sizeof(EFI_GUID))
			goto eof;
		if (memcmp(buf, &SECURE_VARIABLE_GUID, sizeof(EFI_GUID)) == 0)
			break;
	}   
	offset = i;
	printf("Variable header found at offset 0x%x\n", offset);
	lseek(flashfile, offset, SEEK_SET);
	free(buf);
	buf = malloc(sizeof(VARIABLE_STORE_HEADER));
	read(flashfile, buf, sizeof(VARIABLE_STORE_HEADER));

	VARIABLE_STORE_HEADER *vsh = (VARIABLE_STORE_HEADER *)buf;
	if (vsh->Format != VARIABLE_STORE_FORMATTED &&
	    vsh->State != VARIABLE_STORE_HEALTHY) {
		fprintf(stderr, "Variable store header is corrupt\n");
		exit(1);
	}
	UINT32 size = vsh->Size;
	free(buf);
	buf = malloc(size);
	lseek(flashfile, offset, SEEK_SET);
	read(flashfile, buf, size);
	vsh = (VARIABLE_STORE_HEADER *)buf;
	printf("Variable Store Size = 0x%x\n", vsh->Size);

	VARIABLE_HEADER *vh = (void *)HEADER_ALIGN(vsh + 1);
	printf("variables begin at 0x%x\n", (int)((char *)vh - (char *)vsh));
	for (i = 0; IsValidVariableHeader(vh); i++) {
		vh = (void *)HEADER_ALIGN((char *)(vh + 1) + vh->NameSize + vh->DataSize);
	}
	printf("Found %d variables, now at offset %ld\n", i, (long)((char *)vh - (char *)vsh));
	memset(vh, 0, sizeof(*vh));
	vh->StartId = VARIABLE_DATA;
	vh->State = VAR_ADDED;
	vh->Attributes = attributes;
	vh->NameSize = varlen;
	vh->DataSize = varfilesize;
	vh->TimeStamp = timestamp;
	vh->VendorGuid = *owner;

	buf = (void *)(vh + 1);
	memcpy (buf, var, varlen);
	buf += varlen;
	memcpy (buf, vardata, varfilesize);
	lseek(flashfile, offset, SEEK_SET);
	write(flashfile, vsh, vsh->Size);
	close(flashfile);
	
	exit(0);

 eof:
	printf("No variables found in file at offset 0x%x\n", i);
	exit(2);
}

