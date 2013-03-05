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

CHAR16 *loader = L"\\linux-loader.efi";

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

	/* We're in setup mode and the User asked us to add the signature
	 * of this binary to the authorized signatures database */
	if (SetupMode) {
		UINT8 hash[SHA256_DIGEST_SIZE];
		int i;

		sha256_get_pecoff_digest(image, loader, hash);
		Print(L"HASH IS ");
		for (i=0; i<SHA256_DIGEST_SIZE; i++)
			Print(L"%02x", hash[i]);
		Print(L"\n");

		if (find_in_variable_esl(L"db", SIG_DB, hash, SHA256_DIGEST_SIZE) == EFI_SUCCESS)
			goto dont_ask;

		if (ask_install_keys()) {
			UINT8 sig[sizeof(EFI_SIGNATURE_LIST) + sizeof(EFI_SIGNATURE_DATA) - 1 + SHA256_DIGEST_SIZE];
			EFI_SIGNATURE_LIST *l = (void *)sig;
			EFI_SIGNATURE_DATA *d = (void *)(sig + sizeof(EFI_SIGNATURE_LIST));
			SetMem(sig, sizeof(sig), 0);
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
		;
	}

	efi_status = pecoff_execute_image(file, loader, image, systab);
	simple_file_close(file);

	return efi_status;
}
