#include "typedefs.h"

#include <fcntl.h>

#include <x509.h>

int main(int argc, char *argv[])
{
	void *buf;
	int fd;
	struct stat st;
	char out[512];

	fd = open(argv[1], O_RDONLY);
	if (fd<0) {
		fprintf(stderr, "Failed to open file %s\n", argv[1]);
		perror("");
		exit(1);
	}
	fstat(fd, &st);
	buf = malloc(st.st_size);
	read(fd, buf, st.st_size);
	x509_to_str(buf, st.st_size, X509_OBJ_SUBJECT, out, sizeof(out));
	printf("Subject: %s\n", out);
	x509_to_str(buf, st.st_size, X509_OBJ_ISSUER, out, sizeof(out));
	printf("Issuer: %s\n", out);

	exit(0);
}
