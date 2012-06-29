#include <PeImage.h>

EFI_STATUS
pecoff_read_header(PE_COFF_LOADER_IMAGE_CONTEXT *context, void *data);
EFI_STATUS
pecoff_relocate(PE_COFF_LOADER_IMAGE_CONTEXT *context, void **data);
EFI_STATUS
pecoff_image_layout(PE_COFF_LOADER_IMAGE_CONTEXT *context, void **data);

static inline void*
pecoff_image_address(void *image, int size, unsigned int address)
{
	if (address > size)
		return NULL;

	return image + address;
}
