/*
 * Copyright 2012 <James.Bottomley@HansenPartnership.com>
 *
 * see COPYING file
 *
 * Simple elf loader based on Intel TianoCore
 */

#include <efi.h>
#include <efilib.h>

#include <simple_file.h>
#include <pecoff.h>
#include <sha256.h>
#include <variables.h>
#include <console.h>
#include <efiauthenticated.h>
#include <guid.h>

CHAR16 *loader = L"loader.efi";

static void *
ImageAddress (void *image, int size, unsigned int address)
{
        if (address > size)
                return NULL;

        return image + address;
}

/* get the user's permission to boot the image */
int ask_to_boot(void)
{
	return console_yes_no( (CHAR16 *[]) {
		L"WARNING: This Binary is unsigned (and should be a Linux boot loader)",
		L"",
		L"Are you sure you wish to run an unsigned binary",
		L"in a secure environment?",
		L"",
		L"To avoid this question in future place the platform into setup mode",
		L"See http://www.linuxfoundation.org/uefi",
		L"And reboot.",
		NULL,
	});
}
/* Get the user's permission to install the image signature */
static int
ask_install_keys(void)
{
	/* first check to see if the key is already present */
	return console_yes_no( (CHAR16 *[]){ 
		L"You are in Setup Mode",
		L"",
		L"Do you wish me to install the signature",
		L"of the binary into the allowed signatures database?",
		L"",
		L"If you say \"yes\" here, the platform will no longer ask permission",
		L"to run the binary on every boot",
		NULL
	});
}

EFI_STATUS
efi_main (EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
	EFI_STATUS efi_status;
	UINT8 SecureBoot = 0, SetupMode = 0;
	UINTN DataSize = sizeof(SecureBoot);
	EFI_FILE *file;
	void *buffer;
	PE_COFF_LOADER_IMAGE_CONTEXT context;
	EFI_STATUS (EFIAPI *entry_point) (EFI_HANDLE image_handle, EFI_SYSTEM_TABLE *system_table);
	EFI_LOADED_IMAGE *li;
	EFI_DEVICE_PATH *loadpath = NULL;
	CHAR16 *PathName = NULL;
	EFI_HANDLE loader_handle;

	InitializeLib(image, systab);

	efi_status = uefi_call_wrapper(RT->GetVariable, 5, L"SecureBoot", &GV_GUID, NULL, &DataSize, &SecureBoot);

	if (efi_status != EFI_SUCCESS) {
		Print(L"Not a Secure Boot Platform %d\n", efi_status);
	} else	if (!SecureBoot) {
		Print(L"Secure Boot Disabled\n");
		DataSize = sizeof(SetupMode);
	}

	uefi_call_wrapper(RT->GetVariable, 5, L"SetupMode", &GV_GUID, NULL, &DataSize, &SetupMode);

	efi_status = uefi_call_wrapper(BS->HandleProtocol, 3, image,
				       &IMAGE_PROTOCOL, &li);
	if (efi_status != EFI_SUCCESS) {
		Print(L"Failed to init loaded image protocol: %d\n", efi_status);
		return efi_status;
	}

	efi_status = generate_path(loader, li, &loadpath, &PathName);
	if (efi_status != EFI_SUCCESS) {
		Print(L"Unable to generate load path for %s: %d\n", loader,
		      efi_status);
		return efi_status;
	}

	if (!SetupMode) {
		efi_status = uefi_call_wrapper(BS->LoadImage, 6, FALSE, image,
					       loadpath, NULL, 0, &loader_handle);
		if (efi_status == EFI_SUCCESS) {
			/* Image validates - start it */
			Print(L"Starting file via StartImage\n");
			uefi_call_wrapper(BS->StartImage, 3, loader_handle, NULL, NULL);
			uefi_call_wrapper(BS->UnloadImage, 1, loader_handle);
			return EFI_SUCCESS;
		} else {
			Print(L"Failed to load the image: %d\n", efi_status);
		}
	}

	if (SecureBoot) {
		if (ask_to_boot() == 0) {
			/* user told us not to boot this */
			Print(L"Refusing to boot %s\n", loader);
			return EFI_ACCESS_DENIED;
		}
		Print(L"Booting %s with Present User Authorisation\n", loader);
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

	/* We're in setup mode and the User asked us to add the signature
	 * of this binary to the authorized signatures database */
	if (SetupMode) {
		sha256_context ctx;
		UINT8 hash[SHA256_DIGEST_SIZE];
		void *hashbase;
		unsigned int hashsize;
		sha256_starts(&ctx);
		EFI_IMAGE_SECTION_HEADER *section;
		EFI_IMAGE_SECTION_HEADER *sections[context.PEHdr->Pe32.FileHeader.NumberOfSections];
		int  i, sum_of_bytes;

		/* hash start to checksum */
		hashbase = buffer;
		hashsize = (void *)&context.PEHdr->Pe32.OptionalHeader.CheckSum - buffer;
		
		sha256_update(&ctx, hashbase, hashsize);

		/* hash post-checksum to start of certificate table */
		hashbase = (void *)&context.PEHdr->Pe32.OptionalHeader.CheckSum + sizeof (int);
		hashsize = (void *)context.SecDir - hashbase;

		sha256_update(&ctx, hashbase, hashsize);
		
		/* Hash end of certificate table to end of image header */
		hashbase = &context.PEHdr->Pe32Plus.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY + 1];
		hashsize = context.PEHdr->Pe32Plus.OptionalHeader.SizeOfHeaders -
			(int) ((void *) (&context.PEHdr->Pe32Plus.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY + 1]) - buffer);

		sha256_update(&ctx, hashbase, hashsize);
		sum_of_bytes = context.PEHdr->Pe32Plus.OptionalHeader.SizeOfHeaders;
		section = (EFI_IMAGE_SECTION_HEADER *) ((char *)context.PEHdr + sizeof (UINT32) + sizeof (EFI_IMAGE_FILE_HEADER) + context.PEHdr->Pe32.FileHeader.SizeOfOptionalHeader);

		/* Sort the section headers by their data pointers */
		for (i = 0; i < context.PEHdr->Pe32.FileHeader.NumberOfSections; i++) {
			int p = i;
			while (p > 0 && section->PointerToRawData < sections[p - 1]->PointerToRawData) {
				sections[p] = sections[p-1];
				p--;
			}
			sections[p] = section++;
		}
		/* hash the sorted sections */
		for (i = 0; i < context.PEHdr->Pe32.FileHeader.NumberOfSections; i++) {
			section = sections[i];
			hashbase  = ImageAddress(buffer, DataSize, section->PointerToRawData);
			hashsize  = (unsigned int) section->SizeOfRawData;
			if (hashsize == 0)
				continue;
			sha256_update(&ctx, hashbase, hashsize);
			sum_of_bytes += hashsize;
		}

		if (DataSize > sum_of_bytes) {
			/* stuff at end to hash */
			hashbase = buffer + sum_of_bytes;
			hashsize = (unsigned int)(DataSize - context.PEHdr->Pe32Plus.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY].Size - sum_of_bytes);
			sha256_update(&ctx, hashbase, hashsize);
		}
		sha256_finish(&ctx, hash);

		Print(L"HASH IS ");
		for (i=0; i<SHA256_DIGEST_SIZE; i++)
			Print(L"%02x", hash[i]);
		Print(L"\n");

		UINT8 *Data = NULL;

		DataSize = 0;
		efi_status = uefi_call_wrapper(RT->GetVariable, 5, L"db", &SIG_DB, NULL, &DataSize, NULL);
		if (efi_status != EFI_BUFFER_TOO_SMALL)
			goto ask;

		Data = AllocatePool(DataSize);
		if (!Data)
			goto ask;

		efi_status = uefi_call_wrapper(RT->GetVariable, 5, L"db", &SIG_DB, NULL, &DataSize, Data);
		if (efi_status != EFI_SUCCESS)
			goto ask;

		EFI_SIGNATURE_LIST *CertList;

		for (CertList = (EFI_SIGNATURE_LIST *) Data;
		     DataSize > 0
		     && DataSize >= CertList->SignatureListSize;
		     DataSize -= CertList->SignatureListSize,
		     CertList = (EFI_SIGNATURE_LIST *) ((UINT8 *) CertList + CertList->SignatureListSize)) {
			if (CompareGuid(&CertList->SignatureType, &EFI_CERT_SHA256_GUID) != 0)
				continue;
			EFI_SIGNATURE_DATA *Cert  = (EFI_SIGNATURE_DATA *) ((UINT8 *) CertList + sizeof (EFI_SIGNATURE_LIST) + CertList->SignatureHeaderSize);
			if (CompareMem (Cert->SignatureData, hash, SHA256_DIGEST_SIZE) == 0)
				goto dont_ask;
		}
	ask:
		if (ask_install_keys()) {
			UINT8 sig[sizeof(EFI_SIGNATURE_LIST) + sizeof(EFI_SIGNATURE_DATA) - 1 + SHA256_DIGEST_SIZE];
			EFI_SIGNATURE_LIST *l = (void *)sig;
			EFI_SIGNATURE_DATA *d = (void *)sig + sizeof(EFI_SIGNATURE_LIST);
			SetMem(sig, 0, sizeof(sig));
			l->SignatureType = EFI_CERT_SHA256_GUID;
			l->SignatureListSize = sizeof(sig);
			l->SignatureSize = 16 +32; /* UEFI defined */
			CopyMem(&d->SignatureData, hash, sizeof(hash));

			efi_status = SetSecureVariable(L"db", sig, sizeof(sig), SIG_DB, EFI_VARIABLE_APPEND_WRITE, 0);
			if (efi_status != EFI_SUCCESS) {
				Print(L"Failed to add signature to db: %s\n", efi_status);
				return efi_status;
			}
		}
	dont_ask:
		if (Data)
			FreePool(Data);
	}

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
