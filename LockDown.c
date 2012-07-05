#include <efi.h>
#include <efilib.h>

#include <variables.h>

#include "PK.h"
#include "KEK.h"
#include "DB.h"

EFI_GUID GV_GUID = EFI_GLOBAL_VARIABLE;
EFI_GUID SIG_DB = { 0xd719b2cb, 0x3d3a, 0x4596, {0xa3, 0xbc, 0xda, 0xd0,  0xe, 0x67, 0x65, 0x6f }};

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

	efi_status = SetSecureVariable(L"KEK", KEK_cer, KEK_cer_len, GV_GUID);
	if (efi_status != EFI_SUCCESS) {
		Print(L"Failed to enroll KEK: %d\n", efi_status);
		return efi_status;
	}
	efi_status = SetSecureVariable(L"db", DB_cer, DB_cer_len, SIG_DB);
	if (efi_status != EFI_SUCCESS) {
		Print(L"Failed to enroll db: %d\n", efi_status);
		return efi_status;
	}
#if 0
	/* testing revocation ... this will revoke the certificate
	 * we just enrolled in db */
	efi_status = SetSecureVariable(L"dbx", DB_cer, DB_cer_len, SIG_DB);
	if (efi_status != EFI_SUCCESS) {
		Print(L"Failed to enroll dbx: %d\n", efi_status);
		return efi_status;
	}
#endif
	efi_status = SetSecureVariable(L"PK", PK_cer, PK_cer_len, GV_GUID);
	if (efi_status != EFI_SUCCESS) {
		Print(L"Failed to enroll PK: %d\n", efi_status);
		return efi_status;
	}
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
