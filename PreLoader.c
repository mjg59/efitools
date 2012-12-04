/*
 * Copyright 2012 <James.Bottomley@HansenPartnership.com>
 *
 * see COPYING file
 *
 * Simple elf loader based on Intel TianoCore
 */

#include <efi.h>
#include <efilib.h>

#include <guid.h>
#include <pecoff.h>
#include <console.h>
#include <errors.h>

#include "hashlist.h"

CHAR16 *loader = L"\\loader.efi";
CHAR16 *hashtool = L"\\HashTool.efi";

EFI_STATUS
efi_main (EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
	EFI_STATUS status;

	InitializeLib(image, systab);

	/* Transfer from built in hash list to tmpHashList variable */
	uefi_call_wrapper(RT->SetVariable, 5, L"tmpHashList", &MOK_OWNER,
			  EFI_VARIABLE_BOOTSERVICE_ACCESS,
			  (UINTN)_tmp_tmp_hash_len, _tmp_tmp_hash);

	Print(L"ABOUT TO EXECUTE %s\n", loader);
	console_get_keystroke();

	status = pecoff_execute_checked(image, systab, loader);

	if (status == EFI_SUCCESS)
		return status;

	if (status != EFI_SECURITY_VIOLATION && status != EFI_ACCESS_DENIED) {
		CHAR16 buf[256];

		StrCpy(buf, L"Failed to start ");
		StrCat(buf, loader);
		console_error(buf, status);

		return status;
	}

	status = pecoff_execute_checked(image, systab, hashtool);

	if (status != EFI_SUCCESS) {
		CHAR16 buf[256];

		StrCpy(buf, L"Failed to start backup programme ");
		StrCat(buf, hashtool);
		console_error(buf, status);
	}

	/* try to start the loader again */
	status = pecoff_execute_checked(image, systab, loader);


	return status;
}
