LIBFILES = asn1.o asn1_parser.o enumerator.o chunk.o oid.o identification.o \
	x509.o
EFILIBFILES = $(patsubst %.o,%.efi.o,$(LIBFILES))

include ../../Make.rules

libasn1.a: $(LIBFILES)
libasn1-efi.a: $(EFILIBFILES)

test.o: test.c ../../include/x509.h
	$(CC) $(ARCH3264) -I../../include -c -o $@ $<

test: test.o libasn1.a
	$(CC) $(ARCH3264) -o $@ $< libasn1.a

clean:
	rm -f libasn1.a
	rm -f libasn1-efi.a
	rm -f test test.o
	rm -f $(LIBFILES)
	rm -f $(EFILIBFILES)
