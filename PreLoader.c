/*
 * Copyright 2012 <James.Bottomley@HansenPartnership.com>
 *
 * see COPYING file
 *
 */

#include <efi.h>
#include <efilib.h>

#include <console.h>
#include <errors.h>
#include <guid.h>
#include <security_policy.h>
#include <execute.h>

#include "hashlist.h"

CHAR16 *loader = L"loader.efi";
CHAR16 *hashtool = L"HashTool.efi";

EFI_STATUS
efi_main (EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
	EFI_STATUS status;
	UINT8 SecureBoot;
	UINTN DataSize = sizeof(SecureBoot);

	InitializeLib(image, systab);

	console_reset();

	status = uefi_call_wrapper(RT->GetVariable, 5, L"SecureBoot",
				   &GV_GUID, NULL, &DataSize, &SecureBoot);
	if (status != EFI_SUCCESS) {
		Print(L"Not a Secure Boot Platform %d\n", status);
		goto override;
	}

	if (!SecureBoot) {
		Print(L"Secure Boot Disabled\n");
		goto override;
	}

	status = security_policy_install();
	if (status != EFI_SUCCESS) {
		console_error(L"Failed to install override security policy",
			      status);
		/* Don't die, just try to execute without security policy */
		goto override;
	}

	/* install statically compiled in hashes */
	security_protocol_set_hashes(_tmp_tmp_hash, _tmp_tmp_hash_len);

	/* Check for H key being pressed */
	if (console_check_for_keystroke('H'))
		goto start_hashtool;

	status = execute(image, loader);

	if (status == EFI_SUCCESS)
		goto out;

	if (status != EFI_SECURITY_VIOLATION && status != EFI_ACCESS_DENIED) {
		CHAR16 buf[256];

		StrCpy(buf, L"Failed to start ");
		StrCat(buf, loader);
		console_error(buf, status);

		goto out;
	}

	console_alertbox((CHAR16 *[]) {
			L"Failed to start loader",
			L"",
			L"It should be called loader.efi (in the current directory)",
			L"Please enrol its hash and try again",
			L"",
			L"I will now execute HashTool for you to do this",
			NULL
		});

	for (;;) {
	start_hashtool:
		status = execute(image, hashtool);

		if (status != EFI_SUCCESS) {
			CHAR16 buf[256];

			StrCpy(buf, L"Failed to start backup programme ");
			StrCat(buf, hashtool);
			console_error(buf, status);

			goto out;
		}

		/* try to start the loader again */
		status = execute(image, loader);
		if (status == EFI_ACCESS_DENIED
		    || status == EFI_SECURITY_VIOLATION) {
			int selection = console_select((CHAR16 *[]) {
				L"loader is still giving a security error",
				NULL
			}, (CHAR16 *[]) {
				L"Start HashTool",
				L"Exit",
				NULL
			}, 0);
			if (selection == 0)
				continue;
		}

		break;
	}
 out:
	status = security_policy_uninstall();
	if (status != EFI_SUCCESS)
		console_error(L"Failed to uninstall security policy.  Platform needs rebooting", status);

	return status;
 override:
	status = execute(image, loader);
	
	if (status != EFI_SUCCESS) {
		CHAR16 buf[256];

		StrCpy(buf, L"Failed to start ");
		StrCat(buf, loader);
		console_error(buf, status);
	}

	return status;
}
