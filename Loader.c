/* Simple elf loader based on Intel TianoCore */

#include <efi.h>
#include <efilib.h>

#include <simple_file.h>
#include <pecoff.h>

EFI_GUID GV_GUID = EFI_GLOBAL_VARIABLE;
EFI_GUID IMAGE_PROTOCOL = LOADED_IMAGE_PROTOCOL;
EFI_GUID SIMPLE_FS_PROTOCOL = SIMPLE_FILE_SYSTEM_PROTOCOL;

CHAR16 *loader = L"elilo.efi";


EFI_STATUS
efi_main (EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
	EFI_STATUS efi_status;
	UINT8 SecureBoot;
	UINTN DataSize = sizeof(SecureBoot);
	EFI_FILE *file;
	void *buffer;
	PE_COFF_LOADER_IMAGE_CONTEXT context;
	EFI_STATUS (EFIAPI *entry_point) (EFI_HANDLE image_handle, EFI_SYSTEM_TABLE *system_table);

	InitializeLib(image, systab);

	efi_status = uefi_call_wrapper(RT->GetVariable, 5, L"SecureBoot", &GV_GUID, NULL, &DataSize, &SecureBoot);

	if (efi_status != EFI_SUCCESS) {
		Print(L"Not a Secure Boot Platform %d\n", efi_status);
	} else	if (SecureBoot) {
		Print(L"Platform set to boot securely; penguin splash\n");
		//sleep(5);
	} else {
		Print(L"Secure Boot Disabled\n");
	}

	efi_status = simple_file_open(image, loader, &file, EFI_FILE_MODE_READ);
	if (efi_status != EFI_SUCCESS) {
		Print(L"Failed to open %s\n", loader);
		return efi_status;
	}
	efi_status = simple_file_read_all(file, &DataSize, &buffer);
	if (efi_status != EFI_SUCCESS) {
		Print(L"Failed to read %s\n", loader);
		return efi_status;
	}
	Print(L"Read %d bytes from %s\n", DataSize, loader);

	efi_status = pecoff_read_header(&context, buffer);
	if (efi_status != EFI_SUCCESS) {
		Print(L"Failed to read header\n");
		return efi_status;
	}

	Print(L"Image size %d\n", context.ImageSize);

	efi_status = pecoff_relocate(&context, &buffer);
	if (efi_status != EFI_SUCCESS) {
		Print(L"Failed to relocate image\n");
		return efi_status;
	}

	entry_point = pecoff_image_address(buffer, context.ImageSize, context.EntryPoint);
	if (!entry_point) {
		Print(L"Invalid entry point\n");
		return EFI_UNSUPPORTED;
	}

	return uefi_call_wrapper(entry_point, 3, image, systab);

	return EFI_SUCCESS;
}
