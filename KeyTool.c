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
static UINT8 SetupMode, SecureBoot;

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
select_and_apply(CHAR16 **title, CHAR16 *ext, int key, UINTN options)
{
	CHAR16 *file_name;
	EFI_STATUS status;
	EFI_FILE *file;
	EFI_HANDLE h = NULL;

	simple_file_selector(&h, title, NULL, ext, &file_name);
	if (file_name == NULL)
		return;

	status = simple_file_open(h, file_name, &file, EFI_FILE_MODE_READ);
	if (status != EFI_SUCCESS)
		return;

	UINTN size;
	void *esl;
	simple_file_read_all(file, &size, &esl);
	simple_file_close(file);

	/* PK is different: need to update with an authenticated bundle
	 * including a signature with the new PK */
	if (StrCmp(&file_name[StrLen(file_name) - 4], L".esl") == 0) {
		status = SetSecureVariable(keyinfo[key].name, esl, size,
				*keyinfo[key].guid, options, 0);
	} else if (StrCmp(&file_name[StrLen(file_name) - 5], L".auth") == 0) {
		status = uefi_call_wrapper(RT->SetVariable, 5,
					   keyinfo[key].name, keyinfo[key].guid,
					   EFI_VARIABLE_NON_VOLATILE
					   | EFI_VARIABLE_RUNTIME_ACCESS 
					   | EFI_VARIABLE_BOOTSERVICE_ACCESS
					   | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS
					   | options,
				   size, esl);
	} else {
		/* do something about .cer case */
		console_errorbox(L"Handling .cer files is unimplemented");
		return;
	}
	if (status != EFI_SUCCESS) {
		console_error(L"Failed to update variable", status);
		return;
	}
}

static void
show_key(int key, int offset, void *Data, int DataSize)
{
	EFI_SIGNATURE_LIST *CertList;
	EFI_SIGNATURE_DATA *Cert = NULL;
	int cert_count = 0, i, Size, option, offs = 0;
	CHAR16 *title[6], *options[4];
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
	options[0] = L"Delete";
	options[1] = L"Save to File";
	if (key == 0) {
		options[2] = L"Delete with .auth File";
		options[3] = NULL;
	} else {
		options[2] = NULL;
	}
	option = console_select(title, options, 0);
	if (option == -1)
		return;
	if (option == 0) {
		EFI_STATUS status;

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

		status = SetSecureVariable(keyinfo[key].name, Data, DataSize,
					   *keyinfo[key].guid, 0, 0);	
		if (status != EFI_SUCCESS)
			console_error(L"Failed to delete key", status);

	} else if (option == 1) {
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
			CHAR16 str[80];

			SPrint(str, sizeof(str), L"Failed to write %s", filename);
			console_error(str, status);
		}
	} else if (option == 2) {
		title[0] = L"Select authority bundle to remove PK";
		title[1] = NULL;
		select_and_apply(title, L".auth", key, 0);
	}
}

static void
add_new_key(int key, UINTN options)
{
	CHAR16 *title[3];
	/* PK update must be signed: so require .auth file */
	CHAR16 *ext = key ? L".esl|.auth|.cer" : L".auth";

	title[0] = L"Select File containing additional key for";
	title[1] = keyinfo[key].text;
	title[2] = NULL;
	
	select_and_apply(title, ext, key, options);
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
		console_error(L"Failed to get DataSize", efi_status);
		return;
	}

	Data = AllocatePool(DataSize);
	if (!Data) {
		CHAR16 str[80];
		SPrint(str, sizeof(str), L"Failed to allocate %d", DataSize);
		console_errorbox(str);
		return;
	}

	efi_status = uefi_call_wrapper(RT->GetVariable, 5, keyinfo[key].name, keyinfo[key].guid, NULL, &DataSize, Data);
	if (efi_status == EFI_NOT_FOUND) {
		int t = 2;
		title[t++] = L"Variable is Empty";
		if (key == 0)
			title[t++] = L"WARNING: Setting PK will take the platform out of Setup Mode";
		title[t++] = NULL;
	} else if (efi_status != EFI_SUCCESS) {
		console_error(L"Failed to get variable", efi_status);
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

	CHAR16 **guids = (CHAR16 **)AllocatePool((cert_count + 3)*sizeof(void *));
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
	int add = cert_count, replace = cert_count;
	if (key != 0)
		guids[replace++] = L"Add New Key";
	guids[replace] = L"Replace Key(s)";
	guids[replace + 1] = NULL;
	int select = console_select(title, guids, 0);
	FreePool(guids);
	if (select == replace)
		add_new_key(key, 0);
	else if (select == add)
		add_new_key(key, EFI_VARIABLE_APPEND_WRITE);
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

static void
save_keys(void)
{
	EFI_HANDLE vol;
	CHAR16 *volname;

	simple_volume_selector((CHAR16 *[]) {
			L"Save Keys",
			L"",
			L"Select a disk Volume to save all the key files to",
			L"Key files will be saved in the top level directory",
			L"",
			L"Note: For USB volumes, some UEFI implementations aren't",
			L"very good at hotplug, so you may have to boot with the USB",
			L"Key already plugged in to see the volume",
			NULL
		}, &volname, &vol);
	/* no selection or ESC pressed */
	if (!volname)
		return;
	FreePool(volname);

	CHAR16 *title[10], buf[4096], file_name[512];
	CHAR16 *variables[] = { L"PK", L"KEK", L"db", L"dbx" };
	EFI_GUID owners[] = { GV_GUID, GV_GUID, SIG_DB, SIG_DB };
	int i, t_c = 0, b_c = 0;
	UINT8 *data;
	UINTN len;
	EFI_STATUS status;
	EFI_FILE *file;

	title[t_c++] = L"Results of Saving Keys";
	title[t_c++] = L"";

	for (i = 0; i < ARRAY_SIZE(owners); i++) {
		StrCpy(&buf[b_c], variables[i]);

		status = get_variable(variables[i], &data, &len, owners[i]);
		if (status != EFI_SUCCESS) {
			if (status == EFI_NOT_FOUND)
				StrCat(&buf[b_c], L": Variable has no entries");
			else
				StrCat(&buf[b_c], L": Failed to get variable");
			goto cont;
		}
		StrCpy(file_name, L"\\");
		StrCat(file_name, variables[i]);
		StrCat(file_name, L".esl");
		status = simple_file_open(vol, file_name, &file,
					  EFI_FILE_MODE_READ
					  | EFI_FILE_MODE_WRITE
					  | EFI_FILE_MODE_CREATE);
		if (status != EFI_SUCCESS) {
			StrCat(&buf[b_c], L": Failed to open file for writing: ");
			StrCat(&buf[b_c], file_name);
			goto cont;
		}
		status = simple_file_write_all(file, len, data);
		if (status != EFI_SUCCESS) {
			StrCat(&buf[b_c], L": Failed to write to ");
			StrCat(&buf[b_c], file_name);
			goto cont;
		}
		StrCat(&buf[b_c], L": Successfully written to ");
		StrCat(&buf[b_c], file_name);
	cont:
		title[t_c++] = &buf[b_c];
		b_c += StrLen(&buf[b_c]) + 1;
	}
	console_alertbox(title);
}

EFI_STATUS
efi_main (EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
	EFI_STATUS efi_status;
	UINTN DataSize = sizeof(SetupMode);

	im = image;

	InitializeLib(image, systab);

	efi_status = uefi_call_wrapper(RT->GetVariable, 5, L"SetupMode", &GV_GUID, NULL, &DataSize, &SetupMode);

	if (efi_status != EFI_SUCCESS) {
		Print(L"No SetupMode variable ... is platform secure boot enabled?\n");		return EFI_SUCCESS;
	}

	for (;;) {

		CHAR16 line2[80], line3[80], **title;
		int option;

		SetupMode = variable_is_setupmode();
		SecureBoot = variable_is_secureboot();

		line2[0] = line3[0] = L'\0';

		StrCat(line2, L"Platform is in ");
		StrCat(line2, SetupMode ? L"Setup Mode" : L"User Mode");
		StrCat(line3, L"Secure Boot is ");
		StrCat(line3, SecureBoot ? L"on" : L"off");
		title =  (CHAR16 *[]){L"KeyTool main menu", L"", line2, line3, NULL };

		option = console_select(title, (CHAR16 *[]){ L"Save Keys", L"Edit Keys", L"Exit", NULL }, 0);

		switch (option) {
		case 0:
			save_keys();
			break;
		case 1:
			select_key();
			break;
		case 2:
			/* exit from programme */
			return EFI_SUCCESS;
		default:
			break;
		}
	}

	return EFI_SUCCESS;
}
