EFIFILES = HelloWorld.efi LockDown.efi Loader.efi

export TOPDIR	:= $(shell pwd)/

include Make.rules

EFISIGNED = $(patsubst %.efi,%-signed.efi,$(EFIFILES))

all: $(EFISIGNED)

lib/lib.a: FORCE
	make -C lib

PK.crt KEK.crt DB.crt:
	openssl req -new -x509 -newkey rsa:2048 -subj "/CN=$*/" -keyout $*.key -out $@ -days 3650 -nodes

.KEEP: PK.crt KEK.crt DB.crt $(EFIFILES)

LockDown.efi: PK.h KEK.h DB.h

PK.h: PK.cer

KEK.h: KEK.cer

DB.h: DB.cer

Loader.so: lib/lib.a

clean:
	rm -f PK.* KEK.* $(EFIFILES) $(EFISIGNED)

FORCE:



