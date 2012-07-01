/* Read and dump all the secure variables */

#include <efi.h>
#include <efilib.h>

#include <simple_file.h>
#include "efiauthenticated.h"

#define ARRAY_SIZE(a) (sizeof (a) / sizeof ((a)[0]))

EFI_GUID GV_GUID = EFI_GLOBAL_VARIABLE;
EFI_GUID SIG_DB = { 0xd719b2cb, 0x3d3a, 0x4596, {0xa3, 0xbc, 0xda, 0xd0,  0xe, 0x67, 0x65, 0x6f }};

void
parse_db(UINT8 *data, UINTN len)
{
	EFI_SIGNATURE_LIST  *CertList = (EFI_SIGNATURE_LIST *)data;
	EFI_SIGNATURE_DATA  *Cert;
	UINTN Index, count = 0, DataSize = len, CertCount;

	while ((DataSize > 0) && (DataSize >= CertList->SignatureListSize)) {
		count++;
		CertCount = (CertList->SignatureListSize - CertList->SignatureHeaderSize) / CertList->SignatureSize;
		Cert      = (EFI_SIGNATURE_DATA *) ((UINT8 *) CertList + sizeof (EFI_SIGNATURE_LIST) + CertList->SignatureHeaderSize);

		for (Index = 0; Index < CertCount; Index++) {
			Print(L"List %d Signature %d, size %d, Type %g, GUID %g\n",
			      count, Index, CertList->SignatureSize, &CertList->SignatureType, &Cert->SignatureOwner);
			Cert = (EFI_SIGNATURE_DATA *) ((UINT8 *) Cert + CertList->SignatureSize);
		}

		DataSize -= CertList->SignatureListSize;
		CertList = (EFI_SIGNATURE_LIST *) ((UINT8 *) CertList + CertList->SignatureListSize);
	}

}


EFI_STATUS
get_variable(CHAR16 *var, UINT8 **data, UINTN *len, EFI_GUID owner)
{
	EFI_STATUS efi_status;

	*len = 0;

	efi_status = uefi_call_wrapper(RT->GetVariable, 5, var, &owner, NULL,
				       len, NULL);
	if (efi_status != EFI_BUFFER_TOO_SMALL)
		return efi_status;

	*data = AllocateZeroPool(*len);
	if (!data)
		return EFI_OUT_OF_RESOURCES;
	
	efi_status = uefi_call_wrapper(RT->GetVariable, 5, var, &owner, NULL,
				       len, *data);

	if (efi_status != EFI_SUCCESS) {
		FreePool(*data);
		*data = NULL;
	}
	return efi_status;
}

EFI_STATUS
efi_main (EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
	EFI_STATUS efi_status;
	CHAR16 *variables[] = { L"PK", L"KEK", L"db", L"dbx" };
	EFI_GUID owners[] = { GV_GUID, GV_GUID, SIG_DB, SIG_DB };
	UINT8 *data;
	UINTN len;
	int i;

	InitializeLib(image, systab);

	for (i = 0; i < ARRAY_SIZE(owners); i++) {
		efi_status = get_variable(variables[i], &data, &len, owners[i]);
		if (efi_status != EFI_SUCCESS) {
			Print(L"Failed to get %s: %d\n", variables[i], efi_status);
		} else {
			Print(L"Variable %s length %d\n", variables[i], len);
			parse_db(data, len);
			FreePool(data);
		}
	}
	return EFI_SUCCESS;
}
