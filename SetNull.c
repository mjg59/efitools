#include <efi.h>

EFI_STATUS
efi_main (EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
	int *test = NULL;

	*test = 0x123;

	return EFI_SUCCESS;
}
