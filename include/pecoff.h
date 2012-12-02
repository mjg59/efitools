#include <PeImage.h>

EFI_STATUS
pecoff_read_header(PE_COFF_LOADER_IMAGE_CONTEXT *context, void *data);
EFI_STATUS
pecoff_relocate(PE_COFF_LOADER_IMAGE_CONTEXT *context, void **data);
EFI_STATUS
pecoff_image_layout(PE_COFF_LOADER_IMAGE_CONTEXT *context, void **data);
EFI_STATUS
pecoff_execute_checked(EFI_HANDLE image, EFI_SYSTEM_TABLE *systab,
		       CHAR16 *name);
EFI_STATUS
pecoff_execute_image(EFI_FILE *file, CHAR16 *name, EFI_HANDLE image,
		     EFI_SYSTEM_TABLE *systab);

static inline void*
pecoff_image_address(void *image, int size, unsigned int address)
{
	if (address > size)
		return NULL;

	return image + address;
}
