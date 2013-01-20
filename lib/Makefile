LIBFILES = simple_file.o pecoff.o variables.o guid.o sha256.o console.o \
	security_policy.o execute.o configtable.o
EFILIBFILES = $(patsubst %.o,%.efi.o,$(LIBFILES))

include ../Make.rules

lib.a: $(LIBFILES)
lib-efi.a: $(EFILIBFILES)

clean:
	rm -f lib.a
	rm -f $(LIBFILES)

