/* Read and dump all the secure variables */

#include <efi.h>
#include <efilib.h>

#include <simple_file.h>
#include "efiauthenticated.h"

#define ARRAY_SIZE(a) (sizeof (a) / sizeof ((a)[0]))

EFI_GUID GV_GUID = EFI_GLOBAL_VARIABLE;
EFI_GUID SIG_DB = { 0xd719b2cb, 0x3d3a, 0x4596, {0xa3, 0xbc, 0xda, 0xd0,  0xe, 0x67, 0x65, 0x6f }};

EFI_GUID X509_GUID =   { 0xa5c059a1, 0x94e4, 0x4aa7, {0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72} };
EFI_GUID RSA2048_GUID = { 0x3c5766e8, 0x269c, 0x4e34, {0xaa, 0x14, 0xed, 0x77, 0x6e, 0x85, 0xb3, 0xb6} };
EFI_GUID PKCS7_GUID = { 0x4aafd29d, 0x68df, 0x49ee, {0x8a, 0xa9, 0x34, 0x7d, 0x37, 0x56, 0x65, 0xa7} };

void
parse_db(UINT8 *data, UINTN len, EFI_HANDLE image, CHAR16 *name)
{
	EFI_SIGNATURE_LIST  *CertList = (EFI_SIGNATURE_LIST *)data;
	EFI_SIGNATURE_DATA  *Cert;
	UINTN Index, count = 0, DataSize = len, CertCount;
	EFI_FILE *file;
	CHAR16 *buf = AllocatePool(StrLen(name)*2 + 4 + 2 + 4 + 8 +100);
	CHAR16 *ext;
	EFI_STATUS status;

	while ((DataSize > 0) && (DataSize >= CertList->SignatureListSize)) {
		count++;
		CertCount = (CertList->SignatureListSize - CertList->SignatureHeaderSize) / CertList->SignatureSize;
		Cert      = (EFI_SIGNATURE_DATA *) ((UINT8 *) CertList + sizeof (EFI_SIGNATURE_LIST) + CertList->SignatureHeaderSize);

		if (CompareGuid(&CertList->SignatureType, &X509_GUID) == 0) {
			ext = L"X509";
		} else if (CompareGuid(&CertList->SignatureType, &RSA2048_GUID) == 0) {
			ext = L"RSA2048";
		} else if (CompareGuid(&CertList->SignatureType, &PKCS7_GUID) == 0) {
			ext = L"PKCS7";
		} else {
			ext = L"Unknown";
		}

		for (Index = 0; Index < CertCount; Index++) {
			Print(L"List %d Signature %d, size %d, Type %g, GUID %g\n",
			      count, Index, CertList->SignatureSize, &CertList->SignatureType, &Cert->SignatureOwner);
			SPrint(buf, 0, L"%s-%d-%d-%s-%g", name, count, Index, ext, &Cert->SignatureOwner);
			Print(L"Writing to file %s\n", buf);
			status = simple_file_open(image, buf, &file, EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE);
			if (status != EFI_SUCCESS) {
				Print(L"Failed to open file %s: %d\n", buf, status);
				goto cont;
			}
			status = simple_file_write_all(file, CertList->SignatureSize-sizeof(EFI_GUID), Cert->SignatureData);
			if (status != EFI_SUCCESS) {
				Print(L"Failed to write signature to file %s: %d\n", buf, status);
				goto cont;
			}
			simple_file_close(file);

		cont:
			Cert = (EFI_SIGNATURE_DATA *) ((UINT8 *) Cert + CertList->SignatureSize);
		}
		DataSize -= CertList->SignatureListSize;
		CertList = (EFI_SIGNATURE_LIST *) ((UINT8 *) CertList + CertList->SignatureListSize);
	}
	FreePool(buf);
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
		if (efi_status == EFI_NOT_FOUND) {
			Print(L"Variable %s has no entries\n");
		} else if (efi_status != EFI_SUCCESS) {
			Print(L"Failed to get %s: %d\n", variables[i], efi_status);
		} else {
			Print(L"Variable %s length %d\n", variables[i], len);
			parse_db(data, len, image, variables[i]);
			FreePool(data);
		}
	}
	return EFI_SUCCESS;
}
