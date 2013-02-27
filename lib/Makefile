FILES = simple_file.o pecoff.o guid.o sha256.o console.o \
	security_policy.o execute.o configtable.o shell.o
LIBFILES = $(FILES) kernel_efivars.o
EFILIBFILES = $(patsubst %.o,%.efi.o,$(FILES)) variables.o 

include ../Make.rules

lib.a: $(LIBFILES)
lib-efi.a: $(EFILIBFILES)

clean:
	rm -f lib.a
	rm -f $(LIBFILES)

