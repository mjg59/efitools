ARCH	= $(shell uname -m)
INCDIR	   = -I. -I/usr/include/efi -I/usr/include/efi/$(ARCH) -I/usr/include/efi/protocol
CPPFLAGS   = -DCONFIG_$(ARCH)
CFLAGS	   = -O2 -fpic -Wall -fshort-wchar -fno-strict-aliasing -fno-merge-constants
LDFLAGS	   = -nostdlib
CRTOBJS		= /usr/lib64/crt0-efi-$(ARCH).o
# there's a bug in the gnu tools ... the .reloc section has to be
# aligned otherwise the file alignment gets screwed up
LDSCRIPT	= ./elf_$(ARCH)_efi.lds
LDFLAGS		+= -T $(LDSCRIPT) -shared -Bsymbolic $(CRTOBJS) -L /usr/lib64
LOADLIBES	= -lefi -lgnuefi $(shell $(CC) -print-libgcc-file-name)
FORMAT		= efi-app-$(ARCH)
OBJCOPY		= objcopy

ifeq ($(ARCH),x86_64)
  CFLAGS += -DEFI_FUNCTION_WRAPPER
endif

%.efi: %.so
	$(OBJCOPY) -j .text -j .sdata -j .data -j .dynamic -j .dynsym -j .rel \
		-j .rela -j .reloc --target=$(FORMAT) $*.so $@

%.so: %.o
	$(LD) $(LDFLAGS) $^ -o $@ $(LOADLIBES)

%.o: %.c
	$(CC) $(INCDIR) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

all: HelloWorld.efi
