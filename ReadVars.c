/*
 * Copyright 2012 <James.Bottomley@HansenPartnership.com>
 *
 * see COPYING file
 *
 * Read and dump all the secure variables
 */
#include <efi.h>
#include <efilib.h>

#include <simple_file.h>
#include <guid.h>
#include <variables.h>
#include <shell.h>
#include <x509.h>
#include <sha256.h>
#include "efiauthenticated.h"

void
parse_db(UINT8 *data, UINTN len, EFI_HANDLE image, CHAR16 *name, int save_file)
{
	EFI_SIGNATURE_LIST  *CertList = (EFI_SIGNATURE_LIST *)data;
	EFI_SIGNATURE_DATA  *Cert;
	UINTN count = 0, DataSize = len;
	EFI_FILE *file;
	CHAR16 *buf = AllocatePool(StrSize(name) + 4 + 2 + 4 + 8 +100);
	CHAR16 *ext;
	EFI_STATUS status;
	int size;

	certlist_for_each_certentry(CertList, data, size, DataSize) {
		int Index = 0;
		count++;

		if (CompareGuid(&CertList->SignatureType, &X509_GUID) == 0) {
			ext = L"X509";
		} else if (CompareGuid(&CertList->SignatureType, &RSA2048_GUID) == 0) {
			ext = L"RSA2048";
		} else if (CompareGuid(&CertList->SignatureType, &PKCS7_GUID) == 0) {
			ext = L"PKCS7";
		} else if (CompareGuid(&CertList->SignatureType, &EFI_CERT_SHA256_GUID) == 0) {
			ext = L"SHA256";
		} else {
			ext = L"Unknown";
		}

		Print(L"%s: List %d, type %s\n", name, count, ext);

		certentry_for_each_cert(Cert, CertList) {
			Print(L"    Signature %d, size %d, owner %g\n",
			      Index++, CertList->SignatureSize,
			      &Cert->SignatureOwner);

			if (StrCmp(ext, L"X509") == 0) {
				CHAR16 buf1[4096];

				x509_to_str(Cert->SignatureData,
					    CertList->SignatureSize,
					    X509_OBJ_SUBJECT, buf1,
					    sizeof(buf1));
				Print(L"        Subject: %s\n", buf1);

				x509_to_str(Cert->SignatureData,
					    CertList->SignatureSize,
					    X509_OBJ_ISSUER, buf1,
					    sizeof(buf1));
				Print(L"        Issuer: %s\n", buf1);
				
			} else if (StrCmp(ext, L"SHA256") == 0) {
				CHAR16 buf1[256];

				StrCpy(buf1, L"Hash: ");
				sha256_StrCat_hash(buf1, Cert->SignatureData);
				Print(L"        %s\n", buf1);
			}

			if (save_file) {
				SPrint(buf, 0, L"%s-%d-%d-%s-%g", name, count, Index, ext, &Cert->SignatureOwner);
				Print(L"Writing to file %s\n", buf);
				status = simple_file_open(image, buf, &file, EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE);
				if (status != EFI_SUCCESS) {
					Print(L"Failed to open file %s: %d\n", buf, status);
					continue;
				}
				status = simple_file_write_all(file, CertList->SignatureSize-sizeof(EFI_GUID), Cert->SignatureData);
				simple_file_close(file);
				if (status != EFI_SUCCESS) {
					Print(L"Failed to write signature to file %s: %d\n", buf, status);
					continue;
				}
			}

		}
	}
	FreePool(buf);
}

EFI_STATUS
efi_main (EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
	EFI_STATUS status;
	CHAR16 **variables;
	EFI_GUID *owners;
	CHAR16 **ARGV, *progname;
	UINT8 *data;
	UINTN len;
	int i, argc, save_keys = 0, no_print = 0;

	InitializeLib(image, systab);

	if (GetOSIndications() & EFI_OS_INDICATIONS_TIMESTAMP_REVOCATION) {
		variables = (CHAR16 *[]){ L"PK", L"KEK", L"db", L"dbx", L"dbt", L"MokList" , NULL};
		owners = (EFI_GUID []){ GV_GUID, GV_GUID, SIG_DB, SIG_DB, SIG_DB, MOK_OWNER };
	} else {
		variables = (CHAR16 *[]){ L"PK", L"KEK", L"db", L"dbx", L"MokList" , NULL};
		owners = (EFI_GUID []){ GV_GUID, GV_GUID, SIG_DB, SIG_DB, MOK_OWNER };
	}

	status = argsplit(image, &argc, &ARGV);

	if (status != EFI_SUCCESS) {
		Print(L"Failed to parse arguments: %d\n", status);
		return status;
	}

	progname = ARGV[0];
	while (argc > 1 && ARGV[1][0] == L'-') {
		if (StrCmp(ARGV[1], L"-s") == 0) {
			save_keys = 1;
			ARGV += 1;
			argc -= 1;
		} else if (StrCmp(ARGV[1], L"-n") == 0) {
			no_print = 1;
			ARGV += 1;
			argc -= 1;
		} else {
			/* unrecognised option */
			break;
		}
	}

	if ((argc != 2 && argc != 1) || (argc != 1 && no_print)) {
		Print(L"Usage: %s: [-s|-n] [var]\n", progname);
		return EFI_INVALID_PARAMETER;
	}

	if (argc == 1) {
		for (i = 0; variables[i] != NULL; i++) {
			status = get_variable(variables[i], &data, &len, owners[i]);
			if (status == EFI_NOT_FOUND) {
				Print(L"Variable %s has no entries\n", variables[i]);
			} else if (status != EFI_SUCCESS) {
				Print(L"Failed to get %s: %d\n", variables[i], status);
			} else {
				Print(L"Variable %s length %d\n", variables[i], len);
				parse_db(data, len, image, variables[i], save_keys);
				FreePool(data);
			}
		}
	} else {
		CHAR16 *var = ARGV[1];
		
		for(i = 0; variables[i] != NULL; i++) {
			if (StrCmp(var, variables[i]) == 0) {
				break;
			}
		}
		if (variables[i]== NULL) {
			Print(L"Invalid Variable %s\nVariable must be one of: ", var);
			for (i = 0; variables[i] != NULL; i++)
				Print(L"%s ", variables[i]);
			Print(L"\n");
			return EFI_INVALID_PARAMETER;
		}
		status = get_variable(variables[i], &data, &len, owners[i]);
		if (status == EFI_NOT_FOUND) {
			Print(L"Variable %s has no entries\n", variables[i]);
		} else if (status != EFI_SUCCESS) {
			Print(L"Failed to get %s: %d\n", variables[i], status);
		} else {
			Print(L"Variable %s length %d\n", variables[i], len);
			parse_db(data, len, image, variables[i], save_keys);
			FreePool(data);
			parse_db(data, len, image, variables[i], save_keys);
		}
	}
	return EFI_SUCCESS;
}
