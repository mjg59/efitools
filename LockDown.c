/*
 * Copyright 2012 <James.Bottomley@HansenPartnership.com>
 *
 * see COPYING file
 */
#include <efi.h>
#include <efilib.h>

#include <variables.h>
#include <guid.h>

#include "PK.h"
#include "KEK.h"
#include "DB.h"

EFI_STATUS
efi_main (EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
	EFI_STATUS efi_status;
	UINT8 SecureBoot, SetupMode;
	UINTN DataSize = sizeof(SetupMode);

	InitializeLib(image, systab);

	efi_status = uefi_call_wrapper(RT->GetVariable, 5, L"SetupMode", &GV_GUID, NULL, &DataSize, &SetupMode);

	if (efi_status != EFI_SUCCESS) {
		Print(L"No SetupMode variable ... is platform secure boot enabled?\n");
		return EFI_SUCCESS;
	}

	if (!SetupMode) {
		Print(L"Platform is not in Setup Mode, cannot install Keys\n");
		return EFI_SUCCESS;
	}

	Print(L"Platform is in Setup Mode\n");

	efi_status = uefi_call_wrapper(RT->SetVariable, 5, L"KEK", &GV_GUID,
				       EFI_VARIABLE_NON_VOLATILE
				       | EFI_VARIABLE_RUNTIME_ACCESS 
				       | EFI_VARIABLE_BOOTSERVICE_ACCESS
				       | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
				       KEK_auth_len, KEK_auth);
	if (efi_status != EFI_SUCCESS) {
		Print(L"Failed to enroll KEK: %d\n", efi_status);
		return efi_status;
	}
	Print(L"Created KEK Cert\n");
	efi_status = uefi_call_wrapper(RT->SetVariable, 5, L"db", &SIG_DB,
				       EFI_VARIABLE_NON_VOLATILE
				       | EFI_VARIABLE_RUNTIME_ACCESS 
				       | EFI_VARIABLE_BOOTSERVICE_ACCESS
				       | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
				       DB_auth_len, DB_auth);
	if (efi_status != EFI_SUCCESS) {
		Print(L"Failed to enroll db: %d\n", efi_status);
		return efi_status;
	}
	Print(L"Created db Cert\n");
#if 0
	/* testing revocation ... this will revoke the certificate
	 * we just enrolled in db */
	efi_status = SetSecureVariable(L"dbx", DB_cer, DB_cer_len, SIG_DB, 0);
	if (efi_status != EFI_SUCCESS) {
		Print(L"Failed to enroll dbx: %d\n", efi_status);
		return efi_status;
	}
#endif
	/* PK must be updated with a signed copy of itself */
	efi_status = uefi_call_wrapper(RT->SetVariable, 5, L"PK", &GV_GUID,
				       EFI_VARIABLE_NON_VOLATILE
				       | EFI_VARIABLE_RUNTIME_ACCESS 
				       | EFI_VARIABLE_BOOTSERVICE_ACCESS
				       | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
				       PK_auth_len, PK_auth);

	
	if (efi_status != EFI_SUCCESS) {
		Print(L"Failed to enroll PK: %d\n", efi_status);
		return efi_status;
	}
	Print(L"Created PK Cert\n");
	/* enrolling the PK should put us in SetupMode; check this */
	efi_status = uefi_call_wrapper(RT->GetVariable, 5, L"SetupMode", &GV_GUID, NULL, &DataSize, &SetupMode);
	if (efi_status != EFI_SUCCESS) {
		Print(L"Failed to get SetupMode variable: %d\n", efi_status);
		return efi_status;
	}
	Print(L"Platform is in %s Mode\n", SetupMode ? L"Setup" : L"User");

	/* finally, check that SecureBoot is enabled */

	efi_status = uefi_call_wrapper(RT->GetVariable, 5, L"SecureBoot", &GV_GUID, NULL, &DataSize, &SecureBoot);

	if (efi_status != EFI_SUCCESS) {
		Print(L"Failed to get SecureBoot variable: %d\n", efi_status);
		return efi_status;
	}
	Print(L"Platform %s set to boot securely\n", SecureBoot ? L"is" : L"is not");

	return EFI_SUCCESS;
}
