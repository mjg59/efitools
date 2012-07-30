EFIFILES = HelloWorld.efi LockDown.efi Loader.efi ReadVars.efi UpdateVars.efi \
	KeyTool.efi
BINARIES = cert-to-efi-sig-list sig-list-to-certs sign-efi-sig-list

export TOPDIR	:= $(shell pwd)/

include Make.rules

EFISIGNED = $(patsubst %.efi,%-db-signed.efi,$(EFIFILES)) \
	$(patsubst %.efi,%-kek-signed.efi,$(EFIFILES))

all: $(EFISIGNED) $(BINARIES) $(MANPAGES)

install: all
	$(INSTALL) -m 755 -d $(MANDIR)
	$(INSTALL) -m 644 $(MANPAGES) $(MANDIR)
	$(INSTALL) -m 755 -d $(EFIDIR)
	$(INSTALL) -m 755 $(EFIFILES) $(EFIDIR)
	$(INSTALL) -m 755 -d $(BINDIR)
	$(INSTALL) -m 755 $(BINARIES) $(BINDIR)
	$(INSTALL) -m 755 -d $(DOCDIR)
	$(INSTALL) -m 644 README COPYING $(DOCDIR)

lib/lib.a lib/lib-efi.a: FORCE
	$(MAKE) -C lib $(notdir $@)

.SUFFIXES: .crt

PK.crt KEK.crt DB.crt:
	openssl req -new -x509 -newkey rsa:2048 -subj "/CN=$*/" -keyout $*.key -out $@ -days 3650 -nodes -sha256

.KEEP: PK.crt KEK.crt DB.crt PK.key KEK.key DB.key $(EFIFILES)

LockDown.o: PK.h KEK.h DB.h

PK.h: PK.auth

KEK.h: KEK.auth

DB.h: DB.auth

Loader.so: lib/lib-efi.a
ReadVars.so: lib/lib-efi.a
UpdateVars.so: lib/lib-efi.a
LockDown.so: lib/lib-efi.a
KeyTool.so: lib/lib-efi.a

cert-to-efi-sig-list: cert-to-efi-sig-list.o lib/lib.a
	$(CC) -o $@ $< -lcrypto lib/lib.a

sig-list-to-certs: sig-list-to-certs.o lib/lib.a
	$(CC) -o $@ $< -lcrypto lib/lib.a

sign-efi-sig-list: sign-efi-sig-list.o lib/lib.a
	$(CC) -o $@ $< -lcrypto lib/lib.a

clean:
	rm -f PK.* KEK.* DB.* $(EFIFILES) $(EFISIGNED) $(BINARIES) *.o *.so
	rm -f doc/*.1
	$(MAKE) -C lib clean

FORCE:



