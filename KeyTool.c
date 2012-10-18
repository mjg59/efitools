/*
 * Copyright 2012 <James.Bottomley@HansenPartnership.com>
 *
 * see COPYING file
 *
 * Tool for manipulating system keys in setup mode
 */
#include <efi.h>
#include <efilib.h>
#include <console.h>

#include <simple_file.h>
#include <variables.h>
#include <guid.h>
#include "efiauthenticated.h"

static EFI_HANDLE im;

#define ARRAY_SIZE(a) (sizeof (a) / sizeof ((a)[0]))

static struct {
	CHAR16 *name;
	CHAR16 *text;
	EFI_GUID *guid;
	int multiple;
	int sigtypes;
} keyinfo[] = {
	{ .name = L"PK",
	  .text = L"The Platform Key (PK)",
	  .guid = &GV_GUID,
	  .multiple = 0,
	  .sigtypes = 0,
	},
	{ .name = L"KEK",
	  .text = L"The Key Exchange Key Database (KEK)",
	  .guid = &GV_GUID,
	  .multiple = 1,
	  .sigtypes = 0,
	},
	{ .name = L"db",
	  .text = L"The Allowed Signatures Database (db)",
	  .guid = &SIG_DB,
	  .multiple = 1,
	  .sigtypes = 1,
	},
	{ .name = L"dbx",
	  .text = L"The Forbidden Signatures Database (dbx)",
	  .guid = &SIG_DB,
	  .multiple = 1,
	  .sigtypes = 1,
	},
};
static const int keyinfo_size = ARRAY_SIZE(keyinfo);

struct {
	EFI_GUID *guid;
	CHAR16 *name;
} signatures[] = {
	{ .guid = &X509_GUID,
	  .name = L"X509",
	},
	{ .guid = &RSA2048_GUID,
	  .name = L"RSA2048",
	},
	{ .guid = &EFI_CERT_SHA256_GUID,
	  .name = L"SHA256 signature",
	},
};
static const int signatures_size = ARRAY_SIZE(signatures);

static void
show_key(int key, int offset, void *Data, int DataSize)
{
	EFI_SIGNATURE_LIST *CertList;
	EFI_SIGNATURE_DATA *Cert = NULL;
	int cert_count = 0, i, Size, option, offs = 0;
	CHAR16 *title[6];
	CHAR16 str[256], str1[256];

	title[0] = keyinfo[key].text;

	for (CertList = (EFI_SIGNATURE_LIST *) Data, Size = DataSize;
	     Size > 0
		     && Size >= CertList->SignatureListSize;
	     Size -= CertList->SignatureListSize,
		     CertList = (EFI_SIGNATURE_LIST *) ((UINT8 *) CertList + CertList->SignatureListSize)) {
		int count = (CertList->SignatureListSize - sizeof(EFI_SIGNATURE_LIST)) / CertList->SignatureSize;

		Cert  = (EFI_SIGNATURE_DATA *) ((UINT8 *) CertList + sizeof (EFI_SIGNATURE_LIST) + CertList->SignatureHeaderSize);
		if (offset < cert_count + count) {
			offs = cert_count - offset;
			Cert = (EFI_SIGNATURE_DATA *)((void *)Cert + offs*CertList->SignatureSize);
			break;
		}
		cert_count += count;
	}

	SPrint(str, sizeof(str), L"Sig[%d] - owner: %g", offset, &Cert->SignatureOwner);
	Print(L"Got option%s\n\n", str);
	title[1] = str;
	title[2] = L"Unknown";
	
	for (i = 0; i < signatures_size; i++) {
		if (CompareGuid(signatures[i].guid, &CertList->SignatureType) == 0) {
			SPrint(str1, sizeof(str1), L"Type: %s", signatures[i].name);
			title[2] = str1;
			break;
		}
	}
	title[3] = NULL;
	option = console_select(title, (CHAR16 *[]){ L"Back", L"Delete", L"Save to File", NULL }, 0);
	if (option == -1 || option == 0)
		return;
	if (option == 1) {
		Print(L"Old Size %d\n", DataSize);
		if (offs == 0) {
			/* delete entire sig list + data */
			DataSize -= CertList->SignatureListSize;
			if (DataSize > 0)
				CopyMem(CertList,  (void *) CertList + CertList->SignatureListSize, DataSize - ((void *) CertList - Data));
		} else {
			/* only delete single sig */
			DataSize -= CertList->SignatureSize;
			if (DataSize > 0)
				CopyMem(Cert, (void *)Cert + CertList->SignatureSize, DataSize - (Data - (void *)Cert));
		}
		Print(L"New Size %d\n", DataSize);

		SetSecureVariable(keyinfo[key].name, Data, DataSize,
				  *keyinfo[key].guid, 0, 0);	
	} else if (option == 2) {
		CHAR16 *filename;
		EFI_FILE *file;
		EFI_STATUS status;

		filename = AllocatePool(1024);

		SPrint(filename, 0, L"%s-%d.esl", keyinfo[key].name, offset);
		status = simple_file_open(im, filename, &file, EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE);
		if (status == EFI_SUCCESS) {
			status = simple_file_write_all(file, CertList->SignatureListSize, CertList);
			simple_file_close(file);
		}

		if (status != EFI_SUCCESS) {
			Print(L"Failed to write %s: %d\n", filename, status);
			console_get_keystroke();
		}
	}
}

static void
add_new_key(key)
{
	CHAR16 *title[3], *file_name;
	EFI_STATUS status;
	EFI_FILE *file;

	title[0] = L"Select file to add to";
	title[1] = keyinfo[key].text;
	title[2] = NULL;
	simple_file_selector(im, title, L".", L".esl", &file_name);
	if (file_name == NULL)
		return;

	status = simple_file_open(im, file_name, &file, EFI_FILE_MODE_READ);
	if (status != EFI_SUCCESS)
		return;

	UINTN size;
	void *esl;
	simple_file_read_all(file, &size, &esl);
	simple_file_close(file);
	/* FIXME: this won't work for PK */
	status = SetSecureVariable(keyinfo[key].name, esl, size,
				   *keyinfo[key].guid, EFI_VARIABLE_APPEND_WRITE, 0);
	if (status != EFI_SUCCESS) {
		Print(L"Failed to update variable: %d\n", status);
		console_get_keystroke();
		return;
	}
}

static void
manipulate_key(int key)
{
	CHAR16 *title[5];
	EFI_STATUS efi_status;

	title[0] = L"Manipulating Contents of";
	title[1] = keyinfo[key].text;
	title[2] = NULL;

	UINT8 *Data;
	UINTN DataSize = 0, Size;
	efi_status = uefi_call_wrapper(RT->GetVariable, 5, keyinfo[key].name, keyinfo[key].guid, NULL, &DataSize, NULL);
	if (efi_status != EFI_BUFFER_TOO_SMALL && efi_status != EFI_NOT_FOUND) {
		Print(L"Failed to get DataSize\n");
		return;
	}

	Data = AllocatePool(DataSize);
	if (!Data) {
		Print(L"Failed to allocate %d\n", DataSize);
		console_get_keystroke();
		return;
	}

	efi_status = uefi_call_wrapper(RT->GetVariable, 5, keyinfo[key].name, keyinfo[key].guid, NULL, &DataSize, Data);
	if (efi_status == EFI_NOT_FOUND) {
		int t = 2;
		title[t++] = L"Variable is Empty\n";
		if (key == 0)
			title[t++] = L"WARNING: Setting PK will take the platform out of Setup Mode";
		title[t++] = NULL;
	} else if (efi_status != EFI_SUCCESS) {
		Print(L"Failed to get variable %d\n", efi_status);
		console_get_keystroke();
		return;
	}

	EFI_SIGNATURE_LIST *CertList;
	int cert_count = 0;
	for (CertList = (EFI_SIGNATURE_LIST *) Data, Size = DataSize;
	     Size > 0 && Size >= CertList->SignatureListSize;
	     Size -= CertList->SignatureListSize,
		     CertList = (EFI_SIGNATURE_LIST *) ((UINT8 *) CertList + CertList->SignatureListSize)) {
		cert_count += (CertList->SignatureListSize - sizeof(EFI_SIGNATURE_LIST)) / CertList->SignatureSize;
	}

	CHAR16 **guids = (CHAR16 **)AllocatePool((cert_count + 2)*sizeof(void *));
	cert_count = 0;
	for (CertList = (EFI_SIGNATURE_LIST *) Data, Size = DataSize;
	     Size > 0
		     && Size >= CertList->SignatureListSize;
	     Size -= CertList->SignatureListSize,
		     CertList = (EFI_SIGNATURE_LIST *) ((UINT8 *) CertList + CertList->SignatureListSize)) {
		int count = (CertList->SignatureListSize - sizeof(EFI_SIGNATURE_LIST)) / CertList->SignatureSize;
		int j;
		EFI_SIGNATURE_DATA *Cert  = (EFI_SIGNATURE_DATA *) ((UINT8 *) CertList + sizeof (EFI_SIGNATURE_LIST) + CertList->SignatureHeaderSize);
		for (j = 0; j < count; j++) {
			guids[cert_count] = AllocatePool(64*sizeof(CHAR16));
			SPrint(guids[cert_count++], 64*sizeof(CHAR16), L"%g", &Cert[j].SignatureOwner);
		}
	}
	guids[cert_count] = L"Add New Key";
	guids[cert_count + 1] = NULL;
	int select = console_select(title, guids, 0);

	if (select == cert_count)
		add_new_key(key);
	else if (select >= 0)
		show_key(key, select, Data, DataSize);
	FreePool(Data);
}

static void
select_key(void)
{
	int i;
	CHAR16 *keys[keyinfo_size + 1];

	for (i = 0; i < keyinfo_size; i++)
		keys[i] = keyinfo[i].text;
	keys[i] = NULL;

	for (;;) {
		i = console_select( (CHAR16 *[]){ L"Select Key to Manipulate", NULL }, keys, 0);
		if (i == -1)
			break;
		manipulate_key(i);
	}
}


EFI_STATUS
efi_main (EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
	EFI_STATUS efi_status;
	UINT8 SetupMode;
	UINTN DataSize = sizeof(SetupMode);

	im = image;

	InitializeLib(image, systab);

	efi_status = uefi_call_wrapper(RT->GetVariable, 5, L"SetupMode", &GV_GUID, NULL, &DataSize, &SetupMode);

	if (efi_status != EFI_SUCCESS) {
		Print(L"No SetupMode variable ... is platform secure boot enabled?\n");		return EFI_SUCCESS;
	}

	if (!SetupMode) {
		Print(L"Platform is not in Setup Mode, cannot manipulate Keys\n"
		      L"To put your platform into setup mode, see\n"
		      L"http://www.linux-foundation.org/uefi-setup-mode.html\n");
		return EFI_SUCCESS;
	}

	Print(L"Platform is in Setup Mode\n");

	select_key();

	return EFI_SUCCESS;
}
