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
#include <x509.h>
#include <efiauthenticated.h>

static EFI_HANDLE im;
static UINT8 SetupMode, SecureBoot;

#define ARRAY_SIZE(a) (sizeof (a) / sizeof ((a)[0]))

enum {
	KEY_PK = 0,
	KEY_KEK,
	KEY_DB,
	KEY_DBX,
	KEY_MOK,
	MAX_KEYS
};

static struct {
	CHAR16 *name;
	CHAR16 *text;
	EFI_GUID *guid;
	int authenticated:1;
	int hash:1;
} keyinfo[] = {
	[KEY_PK] = {
		.name = L"PK",
		.text = L"The Platform Key (PK)",
		.guid = &GV_GUID,
		.authenticated = 1,
		.hash = 0,
	},
	[KEY_KEK] = {
		.name = L"KEK",
		.text = L"The Key Exchange Key Database (KEK)",
		.guid = &GV_GUID,
		.authenticated = 1,
		.hash = 0,
	},
	[KEY_DB] = {
		.name = L"db",
		.text = L"The Allowed Signatures Database (db)",
		.guid = &SIG_DB,
		.authenticated = 1,
		.hash = 1,
	},
	[KEY_DBX] = {
		.name = L"dbx",
		.text = L"The Forbidden Signatures Database (dbx)",
		.guid = &SIG_DB,
		.authenticated = 1,
		.hash = 1,
	},
	[KEY_MOK] = {
		.name = L"MokList",
		.text = L"The Machine Owner Key List (MokList)",
		.guid = &MOK_OWNER,
		.authenticated = 0,
		.hash = 1,
	}
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
	int use_setsecurevariable = 0;

	simple_file_selector(&h, title, L"\\", ext, &file_name);
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
		if (keyinfo[key].authenticated)
			use_setsecurevariable = 1;
		else
			use_setsecurevariable = 0;
	} else if (StrCmp(&file_name[StrLen(file_name) - 5], L".auth") == 0) {
		use_setsecurevariable = 0;
		options |= EFI_VARIABLE_RUNTIME_ACCESS
			| EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
; 

		if (!keyinfo[key].authenticated) {
			console_errorbox(L"Can't set MOK variables with a .auth file");
			return;
		}
	} else {
		if (keyinfo[key].authenticated)
			use_setsecurevariable = 1;
		else
			use_setsecurevariable = 0;
		void *newesl;
		int newsize;

		status = variable_create_esl(esl, size, &X509_GUID, NULL,
					     &newesl, &newsize);

		if (status != EFI_SUCCESS) {
			console_error(L"Failed to create proper ESL", status);
			return;
		}
		FreePool(esl);
		esl = newesl;
		size = newsize;
	}
	if (use_setsecurevariable) {
		status = SetSecureVariable(keyinfo[key].name, esl, size,
					   *keyinfo[key].guid, options, 0);
	} else {
		status = uefi_call_wrapper(RT->SetVariable, 5,
					   keyinfo[key].name, keyinfo[key].guid,
					   EFI_VARIABLE_NON_VOLATILE
					   | EFI_VARIABLE_BOOTSERVICE_ACCESS
					   | options,
					   size, esl);
	}
	if (status != EFI_SUCCESS) {
		console_error(L"Failed to update variable", status);
		return;
	}
}

static int
StringSplit(CHAR16 *str, int maxlen, CHAR16 c, CHAR16 **out)
{
	int len = StrLen(str);
	int count = 0;

	if (len < maxlen) {
		out[0] = str;
		return 1;
	}
	while (len > 0) {
		int i, found;

		for (i = 0; i < maxlen; i++) {
			if (str[i] == c)
				found = i;
			if (str[i] == '\0') {
				found = i;
				break;
			}
		}
		out[count++] = str;
		str[found] = '\0';
		str = str + found + 1;
		len -= found + 1;
	}
	return count;
}

static void
delete_key(int key, void *Data, int DataSize, EFI_SIGNATURE_LIST *CertList,
	   EFI_SIGNATURE_DATA *Cert)
{
	EFI_STATUS status;
	int certs = (CertList->SignatureListSize - sizeof(EFI_SIGNATURE_LIST) - CertList->SignatureHeaderSize) / CertList->SignatureSize;

	if (certs == 1) {
		/* delete entire sig list + data */
		DataSize -= CertList->SignatureListSize;
		if (DataSize > 0)
			CopyMem(CertList,  (void *) CertList + CertList->SignatureListSize, DataSize - ((void *) CertList - Data));
	} else {
		int remain = DataSize - ((void *)Cert - Data) - CertList->SignatureSize;
		/* only delete single sig */
		DataSize -= CertList->SignatureSize;
		CertList->SignatureListSize -= CertList->SignatureSize;
		if (remain > 0)
			CopyMem(Cert, (void *)Cert + CertList->SignatureSize, remain);
	}

	if (keyinfo[key].authenticated)
		status = SetSecureVariable(keyinfo[key].name, Data,
					   DataSize,
					   *keyinfo[key].guid, 0, 0);
	else
		status = uefi_call_wrapper(RT->SetVariable, 5,
					   keyinfo[key].name, keyinfo[key].guid,
					   EFI_VARIABLE_NON_VOLATILE
					   | EFI_VARIABLE_BOOTSERVICE_ACCESS,
					   DataSize, Data);

	if (status != EFI_SUCCESS)
		console_error(L"Failed to delete key", status);
}

static void
show_key(int key, int offset, void *Data, int DataSize)
{
	EFI_SIGNATURE_LIST *CertList;
	EFI_SIGNATURE_DATA *Cert = NULL;
	int cert_count = 0, i, Size, option = 0;
	CHAR16 *title[20], *options[4];
	CHAR16 str[256], str1[256], str2[256];

	title[0] = keyinfo[key].text;

	certlist_for_each_certentry(CertList, Data, Size, DataSize) {
		certentry_for_each_cert(Cert, CertList)
			if (cert_count++ == offset)
				goto finished;
	}
 finished:

	SPrint(str, sizeof(str), L"Sig[%d] - owner: %g", offset, &Cert->SignatureOwner);

	int c = 0;
	title[c++] = str;
	title[c] = L"Unknown";
	
	for (i = 0; i < signatures_size; i++) {
		if (CompareGuid(signatures[i].guid, &CertList->SignatureType) == 0) {
			SPrint(str1, sizeof(str1), L"Type: %s", signatures[i].name);
			title[c] = str1;
			break;
		}
	}
	CHAR16 buf[1024], buf1[1024], *tmpbuf[10], *tmpbuf1[10];
	if (CompareGuid(&CertList->SignatureType, &EFI_CERT_SHA256_GUID) == 0) {
		StrCpy(str2, L"Hash: ");
		sha256_StrCat_hash(str2, Cert->SignatureData);
		title[++c] = str2;
	} else if (CompareGuid(&CertList->SignatureType, &X509_GUID) == 0) {

		x509_to_str(Cert->SignatureData,
			    CertList->SignatureSize,
			    X509_OBJ_SUBJECT, buf, sizeof(buf));

		title[++c] = L"";
		title[++c] = L"Subject:";


		int sp = StringSplit(buf, 70, ',', tmpbuf);

		for (i = 0; i < sp; i++)
			title[++c] = tmpbuf[i];

		x509_to_str(Cert->SignatureData,
			    CertList->SignatureSize,
			    X509_OBJ_ISSUER, buf1, sizeof(buf1));

		sp = StringSplit(buf1, 70, ',', tmpbuf1);
	
		title[++c] = L"Issuer:";
		for (i = 0; i < sp; i++)
			title[++c] = tmpbuf1[i];
	}
	title[++c] = NULL;

	int o = 0;
	int option_delete = NOSEL, option_delete_w_auth = NOSEL,
		option_save = NOSEL;

	if (variable_is_setupmode() || key == KEY_MOK) {
		option_delete = o;
		options[o++] = L"Delete";
	}
	option_save = o;
	options[o++] = L"Save to File";
	if (key == KEY_PK) {
		option_delete_w_auth = o;
		options[o++] = L"Delete with .auth File";
	}
	options[o++] = NULL;
	option = console_select(title, options, option);
	if (option == -1)
		return;
	if (option == option_delete) {
		delete_key(key, Data, DataSize, CertList, Cert);
	} else if (option == option_save) {
		CHAR16 *filename;
		EFI_FILE *file;
		EFI_STATUS status;
		EFI_HANDLE vol;
		CHAR16 *volname;

		simple_volume_selector((CHAR16 *[]) {
				L"Save Key",
				L"",
				L"Select a disk Volume to save the key file to",
				L"The Key file will be saved in the top level directory",
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

		filename = AllocatePool(1024);

		SPrint(filename, 0, L"%s-%d.esl", keyinfo[key].name, offset);
		status = simple_file_open(vol, filename, &file, EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE);
		if (status == EFI_SUCCESS) {
			status = simple_file_write_all(file, CertList->SignatureListSize, CertList);
			simple_file_close(file);
		}

		if (status != EFI_SUCCESS) {
			CHAR16 str[80];

			SPrint(str, sizeof(str), L"Failed to write %s", filename);
			console_error(str, status);
		} else {
			CHAR16 str1[80], str2[80], str3[80];
			
			SPrint(str1, sizeof(str1), L"Key %s[%d]", keyinfo[key].name, offset);
			SPrint(str2, sizeof(str2), L"With GUID: %g", &Cert->SignatureOwner);
			SPrint(str3, sizeof(str3), L"saved to %s", filename);

			console_alertbox((CHAR16 *[]) {
					L"Successfully Saved",
					L"",
					str1,
					str2,
					str3,
					NULL
				});
		}
		FreePool(filename);
	} else if (option == option_delete_w_auth) {
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
	CHAR16 *ext = (key != KEY_PK && variable_is_setupmode())
		? L".esl|.auth|.cer" : L".auth";

	title[0] = L"Select File containing additional key for";
	title[1] = keyinfo[key].text;
	title[2] = NULL;
	
	select_and_apply(title, ext, key, options);
}

static void
enroll_hash(int key)
{
	EFI_STATUS efi_status;
	CHAR16 *file_name = NULL, *title[6], buf0[256], buf1[256], buf2[256];
	UINT8 hash[SHA256_DIGEST_SIZE];
	int i;
	EFI_HANDLE h = NULL;

	simple_file_selector(&h, (CHAR16 *[]){
			L"Select Binary",
			L"",
			L"The Selected Binary will have its hash Enrolled",
			L"This means it will Subsequently Boot with no prompting",
			L"Remember to make sure it is a genuine binary before Enrolling its hash",
			NULL
		}, L"\\", NULL, &file_name);

	if (!file_name)
		/* user pressed ESC */
		return;

	efi_status = sha256_get_pecoff_digest(h, file_name, hash);
	if (efi_status != EFI_SUCCESS) {
		console_error(L"Hash failed (is efi binary valid?)",
			      efi_status);
		return;
	}
	
	StrCpy(buf0, L"Enroll hash into ");
	StrCat(buf0, keyinfo[key].text);
	title[0] = buf0;
	title[1] = L"";
	StrCpy(buf1, L"File: ");
	StrCat(buf1, file_name);
	title[2] = buf1;
	StrCpy(buf2, L"Hash: ");
	sha256_StrCat_hash(buf2, hash);
	title[3] = buf2;
	title[4] = NULL;
	i = console_yes_no(title);
	if (i == 0)
		return;

	efi_status = variable_enroll_hash(keyinfo[key].name,
					  *keyinfo[key].guid, hash);	
	if (efi_status != EFI_SUCCESS && efi_status != EFI_ALREADY_STARTED) {
		console_error(L"Failed to add signature to db", efi_status);
		return;
	}
}

static void
save_key_internal(int key, EFI_HANDLE vol, CHAR16 *error)
{
	CHAR16 *variables[] = { 
		[KEY_PK] = L"PK",
		[KEY_KEK] = L"KEK",
		[KEY_DB] = L"db",
		[KEY_DBX] = L"dbx",
		[KEY_MOK] = L"MokList"
	};
	EFI_GUID owners[] = { 
		[KEY_PK] = GV_GUID,
		[KEY_KEK] = GV_GUID,
		[KEY_DB] = SIG_DB,
		[KEY_DBX] = SIG_DB,
		[KEY_MOK] = MOK_OWNER
	};
	EFI_STATUS status;
	EFI_FILE *file;
	UINT8 *data;
	UINTN len;
	CHAR16 file_name[512];

	StrCpy(error, variables[key]);
	status = get_variable(variables[key], &data, &len, owners[key]);
	if (status != EFI_SUCCESS) {
		if (status == EFI_NOT_FOUND)
			StrCat(error, L": Variable has no entries");
		else
			SPrint(error, 1024, L"%s: Failed to get variable (Error: %d)",
			       error, status);
		return;
	}
	StrCpy(file_name, L"\\");
	StrCat(file_name, variables[key]);
	StrCat(file_name, L".esl");
	status = simple_file_open(vol, file_name, &file,
				  EFI_FILE_MODE_READ
				  | EFI_FILE_MODE_WRITE
				  | EFI_FILE_MODE_CREATE);
	if (status != EFI_SUCCESS) {
		SPrint(error, 1024, L"%s: Failed to open file %s (Error: %d)",
		       error, file_name, status);
		return;
	}
	status = simple_file_write_all(file, len, data);
	simple_file_close(file);
	if (status != EFI_SUCCESS) {
		SPrint(error, 1024, L"%s: Failed to write to %s (Error: %d)",
		       error, file_name, status);
		return;
	}
	StrCat(error, L": Successfully written to ");
	StrCat(error, file_name);
}

static void
save_key(int key)
{
	EFI_HANDLE vol;
	CHAR16 *volname;

	simple_volume_selector((CHAR16 *[]) {
			L"Save Key",
			L"",
			L"Select a disk Volume to save the key file to",
			L"The key file will be saved in the top level directory",
			L"",
			L"Note: For USB volumes, some UEFI implementations aren't",
			L"very good at hotplug, so you may have to boot with the USB",
			L"USB device already plugged in to see the volume",
			NULL
		}, &volname, &vol);
	/* no selection or ESC pressed */
	if (!volname)
		return;
	FreePool(volname);

	CHAR16 buf[1024], *title[2];

	save_key_internal(key, vol, buf);
	title[0] = buf;
	title[1] = NULL;

	console_alertbox(title);
}

static void
manipulate_key(int key)
{
	CHAR16 *title[5];
	EFI_STATUS efi_status;
	int setup_mode = variable_is_setupmode(), i;

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
		if (key == KEY_PK)
			title[t++] = L"WARNING: Setting PK will take the platform out of Setup Mode";
		title[t++] = NULL;
	} else if (efi_status != EFI_SUCCESS) {
		console_error(L"Failed to get variable", efi_status);
		return;
	}

	EFI_SIGNATURE_LIST *CertList;
	int cert_count = 0, add = NOSEL, replace = NOSEL, hash = NOSEL,
		save = NOSEL;
	certlist_for_each_certentry(CertList, Data, Size, DataSize) {
		cert_count += (CertList->SignatureListSize - sizeof(EFI_SIGNATURE_LIST) - CertList->SignatureHeaderSize) / CertList->SignatureSize;
	}

	CHAR16 **guids = (CHAR16 **)AllocatePool((cert_count + 5)*sizeof(void *));
	cert_count = 0;
	int g;
	certlist_for_each_certentry(CertList, Data, Size, DataSize) {
		EFI_SIGNATURE_DATA *Cert;

		certentry_for_each_cert(Cert, CertList) {
			guids[cert_count] = AllocatePool(64*sizeof(CHAR16));
			SPrint(guids[cert_count++], 64*sizeof(CHAR16), L"%g", &Cert->SignatureOwner);
		}
	}
	g = cert_count;
	if (key != 0) {
		add = g;
		guids[g++] = L"Add New Key";
	}
	replace = g;
	guids[g++] = L"Replace Key(s)";

	if (keyinfo[key].hash && (!keyinfo[key].authenticated || setup_mode)) {
		hash = g;
		guids[g++] = L"Enroll hash of binary";
	}

	if (cert_count != 0) {
		save = g;
		guids[g++] = L"Save key";
	}

	guids[g] = NULL;
	int select = console_select(title, guids, 0);
	for (i = 0; i < cert_count; i++)
		FreePool(guids[i]);
	FreePool(guids);
	if (select == replace)
		add_new_key(key, 0);
	else if (select == add)
		add_new_key(key, EFI_VARIABLE_APPEND_WRITE);
	else if (select == hash)
		enroll_hash(key);
	else if (select == save)
		save_key(key);
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

	i = 0;

	for (;;) {
		i = console_select( (CHAR16 *[]){ L"Select Key to Manipulate", NULL }, keys, i);
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
			L"USB device already plugged in to see the volume",
			NULL
		}, &volname, &vol);
	/* no selection or ESC pressed */
	if (!volname)
		return;
	FreePool(volname);

	CHAR16 *title[10], buf[8000];
	int i, t_c = 0, b_c = 0;

	title[t_c++] = L"Results of Saving Keys";
	title[t_c++] = L"";

	for (i = 0; i < MAX_KEYS; i++) {
		save_key_internal(i, vol, &buf[b_c]);
		title[t_c++] = &buf[b_c];
		b_c += StrLen(&buf[b_c]) + 1;
	}
	title[t_c] = NULL;
	console_alertbox(title);
}

EFI_STATUS
efi_main (EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
	EFI_STATUS efi_status;
	UINTN DataSize = sizeof(SetupMode);
	int option = 0;

	im = image;

	InitializeLib(image, systab);

	efi_status = uefi_call_wrapper(RT->GetVariable, 5, L"SetupMode", &GV_GUID, NULL, &DataSize, &SetupMode);

	if (efi_status != EFI_SUCCESS) {
		Print(L"No SetupMode variable ... is platform secure boot enabled?\n");		return EFI_SUCCESS;
	}

	for (;;) {

		CHAR16 line2[80], line3[80], **title;

		SetupMode = variable_is_setupmode();
		SecureBoot = variable_is_secureboot();

		line2[0] = line3[0] = L'\0';

		StrCat(line2, L"Platform is in ");
		StrCat(line2, SetupMode ? L"Setup Mode" : L"User Mode");
		StrCat(line3, L"Secure Boot is ");
		StrCat(line3, SecureBoot ? L"on" : L"off");
		title =  (CHAR16 *[]){L"KeyTool main menu", L"", line2, line3, NULL };

		option = console_select(title, (CHAR16 *[]){ L"Save Keys", L"Edit Keys", L"Exit", NULL }, option);

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
