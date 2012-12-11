LIBFILES = asn1.o asn1_parser.o enumerator.o chunk.o oid.o identification.o \
	x509.o
EFILIBFILES = $(patsubst %.o,%.efi.o,$(LIBFILES))

include ../../Make.rules

libasn1.a: $(LIBFILES)
libasn1-efi.a: $(EFILIBFILES)

test.o: test.c ../../include/x509.h
	$(CC) -I../../include -c -o $@ $<

test: test.o libasn1.a
	$(CC) -o $@ $< libasn1.a
