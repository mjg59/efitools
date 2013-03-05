/*
 * Copyright 2012 <James.Bottomley@HansenPartnership.com>
 *
 * see COPYING file
 *
 * Update a secure varible when in secure mode
 *
 * For instance append a signature to the KEK, db or dbx datbases
 */
#include <efi.h>
#include <efilib.h>

#include <simple_file.h>
#include <guid.h>
#include <variables.h>
#include <shell.h>
#include "efiauthenticated.h"

#define ARRAY_SIZE(a) (sizeof (a) / sizeof ((a)[0]))

EFI_STATUS
efi_main (EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
	EFI_STATUS status;
	int argc, i, esl_mode = 0, hash_mode = 0;
	CHAR16 **ARGV, *var, *name, *progname, *owner_guid;
	EFI_FILE *file;
	void *buf;
	UINTN size, options = 0;
	EFI_GUID *owner;
	CHAR16 *variables[] = { L"PK", L"KEK", L"db", L"dbx", L"MokList" };
	EFI_GUID *owners[] = { &GV_GUID, &GV_GUID, &SIG_DB, &SIG_DB,
			       &MOK_OWNER };

	InitializeLib(image, systab);

	status = argsplit(image, &argc, &ARGV);

	if (status != EFI_SUCCESS) {
		Print(L"Failed to parse arguments: %d\n", status);
		return status;
	}

	progname = ARGV[0];
	while (argc > 1 && ARGV[1][0] == L'-') {
		if (StrCmp(ARGV[1], L"-a") == 0) {
			options |= EFI_VARIABLE_APPEND_WRITE;
			ARGV += 1;
			argc -= 1;
		} else if (StrCmp(ARGV[1], L"-g") == 0) {
			owner_guid = ARGV[2];
			ARGV += 2;
			argc -= 2;
		} else if (StrCmp(ARGV[1], L"-e") == 0) {
			esl_mode = 1;
			ARGV += 1;
			argc -= 1;
		} else if (StrCmp(ARGV[1], L"-b") == 0) {
			esl_mode = 1;
			hash_mode = 1;
			ARGV += 1;
			argc -= 1;
		} else {
			/* unrecognised option */
			break;
		}
	}

	if (argc != 3 ) {
		Print(L"Usage: %s: [-g guid] [-a] [-e] [-b] var file\n", progname);
		return EFI_INVALID_PARAMETER;
	}

	var = ARGV[1];
	name = ARGV[2];

	for(i = 0; i < ARRAY_SIZE(variables); i++) {
		if (StrCmp(var, variables[i]) == 0) {
			owner = owners[i];
			break;
		}
	}
	if (i == ARRAY_SIZE(variables)) {
		Print(L"Invalid Variable %s\nVariable must be one of: ", var);
		for (i = 0; i < ARRAY_SIZE(variables); i++)
			Print(L"%s ", variables[i]);
		Print(L"\n");
		return EFI_INVALID_PARAMETER;
	}

	if (owner == &MOK_OWNER) {
		if (!esl_mode) {
			Print(L"MoK variables can only be updated in ESL mode\n");
			return EFI_INVALID_PARAMETER;
		}
		/* hack: esl goes directly into MoK variables, so we now
		 * pretend we have a direct .auth update */
		esl_mode = 0;
	} else {
		/* non MoK variables have runtime access and time based
		 * authentication, MoK ones don't */
		options |= EFI_VARIABLE_RUNTIME_ACCESS
			| EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
	}
		

	status = simple_file_open(image, name, &file, EFI_FILE_MODE_READ);
	if (status != EFI_SUCCESS) {
		Print(L"Failed to open file %s\n", name);
		return status;
	}

	status = simple_file_read_all(file, &size, &buf);
	if (status != EFI_SUCCESS) {
		Print(L"Failed to read file %s\n", name);
		return status;
	}
	simple_file_close(file);

	if (hash_mode) {
		UINT8 hash[SHA256_DIGEST_SIZE];

		status = sha256_get_pecoff_digest_mem(buf, size, hash);
		if (status != EFI_SUCCESS) {
			Print(L"Failed to get hash of %s\n", name);
			return status;
		}
		status = variable_enroll_hash(var, *owner, hash);
	} else if (esl_mode) {
		status = SetSecureVariable(var, buf, size, *owner, options, 0);
	} else {
		status = uefi_call_wrapper(RT->SetVariable, 5, var, owner,
					   EFI_VARIABLE_NON_VOLATILE
					   | EFI_VARIABLE_BOOTSERVICE_ACCESS
					   | options,
					   size, buf);
	}

	if (status != EFI_SUCCESS) {
		Print(L"Failed to update variable %s: %d\n", var, status);
		return status;
	}
	return EFI_SUCCESS;
}
