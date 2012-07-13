EFIFILES = HelloWorld.efi LockDown.efi Loader.efi ReadVars.efi UpdateVars.efi
BINARIES = cert-to-efi-sig-list sig-list-to-certs sign-efi-sig-list

export TOPDIR	:= $(shell pwd)/

include Make.rules

EFISIGNED = $(patsubst %.efi,%-db-signed.efi,$(EFIFILES)) \
	$(patsubst %.efi,%-kek-signed.efi,$(EFIFILES))

all: $(EFISIGNED) $(BINARIES)

lib/lib.a: FORCE
	make -C lib

.SUFFIXES: .crt

PK.crt KEK.crt DB.crt:
	openssl req -new -x509 -newkey rsa:2048 -subj "/CN=$*/" -keyout $*.key -out $@ -days 3650 -nodes

.KEEP: PK.crt KEK.crt DB.crt PK.key KEK.key DB.key $(EFIFILES)

LockDown.efi: PK.h KEK.h DB.h

PK.h: PK.cer

KEK.h: KEK.cer

DB.h: DB.cer

Loader.so: lib/lib.a
ReadVars.so: lib/lib.a
UpdateVars.so: lib/lib.a
LockDown.so: lib/lib.a

cert-to-efi-sig-list: cert-to-efi-sig-list.o
	$(CC) -o $@ $< -lcrypto

sig-list-to-certs: sig-list-to-certs.o
	$(CC) -o $@ $< -lcrypto

sign-efi-sig-list: sign-efi-sig-list.o
	$(CC) -o $@ $< -lcrypto

clean:
	rm -f PK.* KEK.* DB.* $(EFIFILES) $(EFISIGNED) $(BINARIES) *.o *.so

FORCE:



