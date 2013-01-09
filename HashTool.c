/*
 * Copyright 2012 <James.Bottomley@HansenPartnership.com>
 *
 * see COPYING file
 *
 * Simple key manager for both MOK and SecureBoot variables
 */

#include <efi.h>
#include <efilib.h>

#include <simple_file.h>
#include <sha256.h>
#include <variables.h>
#include <console.h>
#include <efiauthenticated.h>
#include <guid.h>
#include <execute.h>

static CHAR16* keytoolbin = L"KeyTool.efi";
static int transition_to_setup = 0, reboot_to_uefi_menu = 0;
static EFI_HANDLE im;

#if 0
/* some UEFI machines have a buggy implementation
 * see if we can tip the system into Setup Mode */
static EFI_STATUS
change_setup_mode(int user_mode)
{
	static UINT8 *data = NULL;
	static UINTN len = 0;
	EFI_STATUS status;

	if (user_mode) {
		if (!data)
			/* can only do this if we previously reset to setup */
			return EFI_INVALID_PARAMETER;

		status = SetSecureVariable(L"PK", data, len, GV_GUID, 0, 0);	

		if (status == EFI_SUCCESS) {
			data = NULL;
			len = 0;
		}
		return status;
		
	} else {
		status = get_variable(L"PK", &data, &len, GV_GUID);
		if (status != EFI_SUCCESS)
			return status;
		/* try to update it to nothing */
		return SetSecureVariable(L"PK", data, 0, GV_GUID, 0, 0);	
	}

}
#endif

static void
enroll_hash(void)
{
	EFI_STATUS efi_status;
	CHAR16 *file_name = NULL, *title[6], buf0[256], buf1[256], buf2[256],
		*var;
	EFI_GUID *owner;
	UINT8 hash[SHA256_DIGEST_SIZE];
	int i, setupmode = variable_is_setupmode();

	simple_file_selector(&im, (CHAR16 *[]){
			L"Select Binary",
			L"",
			L"The Selected Binary will have its hash Enrolled",
			L"This means it will Subsequently Boot with no prompting",
			L"Remember to make sure it is a genuine binary before Enroling its hash",
			NULL
		}, L"\\", L"", &file_name);

	if (!file_name)
		/* user pressed ESC */
		return;

	efi_status = sha256_get_pecoff_digest(im, file_name, hash);
	if (efi_status != EFI_SUCCESS) {
		console_error(L"Hash failed (is efi binary valid?)",
			      efi_status);
		return;
	}

	
	StrCpy(buf0, L"Enroll this hash into ");
	if (setupmode)
		StrCat(buf0, L"UEFI signature database?");
	else
		StrCat(buf0, L"MOK database?");
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

	/* We're in setup mode and the User asked us to add the signature
	 * of this binary to the authorized signatures database */
	if (setupmode) {
		var = L"db";
		owner = &SIG_DB;
	} else {
		var = L"MokList";
		owner = &MOK_OWNER;
	}

	efi_status = variable_enroll_hash(var, *owner, hash);	
	if (efi_status != EFI_SUCCESS && efi_status != EFI_ALREADY_STARTED) {
		console_error(L"Failed to add signature to db", efi_status);
		return;
	}
}

void
transition_to_uefi_menu(void)
{
	int option;
	UINT64 indications = GetOSIndications();

	if ((indications & EFI_OS_INDICATIONS_BOOT_TO_FW_UI) == 0) {
		console_errorbox(L"Platform Does not Support rebooting to firmware menu");
		return;
	}

	option = console_yes_no( (CHAR16 *[]){
			L"About to reboot to UEFI Setup Menu",
			L"",
			L"For more details about your system's setup menu",
			L"Including how to reset the system to setup mode, see",
			L"",
			L"http://www.linuxfoundation.org/uefi",
			NULL
		});
	/* user said no */
	if (option == 0)
		return;

	SETOSIndicationsAndReboot(EFI_OS_INDICATIONS_BOOT_TO_FW_UI);

	return;
}

EFI_STATUS
efi_main (EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
	UINT64 indications;
	int option = 0;

	im = image;

	InitializeLib(image, systab);

	indications = GetOSIndications();

	if (indications & EFI_OS_INDICATIONS_BOOT_TO_FW_UI)
		reboot_to_uefi_menu = 1;

#if 0
	/*
	 * Microsoft objects to this code.  What it does is test to see
	 * if the platform key is removable and offer a menu item to 
	 * transition to setup mode
	 */
	if (!variable_is_setupmode()) {
		if (change_setup_mode(0) == EFI_SUCCESS) {
			transition_to_setup = 1;
			change_setup_mode(1);
		}
	}
#endif

	for (;;) {

		CHAR16 line2[80], line3[80], **title, *options[6];
		int c = 0, setup_mode = NOSEL, uefi_reboot = NOSEL,
			reboot = NOSEL,	exit_moktool = NOSEL, SetupMode,
			setup_mode_arg = 0, keytool = NOSEL;
		EFI_FILE *file;

		if (simple_file_open(image, keytoolbin, &file, EFI_FILE_MODE_READ)
		    == EFI_SUCCESS) {
			keytool = 1;
			simple_file_close(file);
		}
		
		SetupMode = variable_is_setupmode();

		StrCpy(line2, L"Platform is in ");
		StrCat(line2, SetupMode ? L"Setup Mode" : L"User Mode");
		StrCpy(line3, L"Secure Boot is ");
		StrCat(line3, variable_is_secureboot() ? L"on" : L"off");
		title =  (CHAR16 *[]){L"Hash Tool main menu", L"", line2, line3, NULL };
		options[c++] = L"Enroll Hash";
		if (keytool != NOSEL) {
			keytool = c;
			options[c++] = L"Start UEFI Key Tool";
		}

		if (transition_to_setup) {
			setup_mode = c;

			if (SetupMode) {
				setup_mode_arg = 1;
				options[c++] = L"Enter User Mode";
			} else {
				setup_mode_arg = 0;
				options[c++] = L"Enter Setup Mode";
			}
		}
		if (reboot_to_uefi_menu) {
			uefi_reboot = c;

			options[c++] = L"Reboot to UEFI Menu";
		}

		reboot = c;
		options[c++] = L"Reboot System";
		exit_moktool = c;
		options[c++] = L"Exit";
		options[c++] = NULL;

		option = console_select(title, options, option);

		if (option == 0) {
			enroll_hash();
		} else if (option == keytool) {
			EFI_STATUS status;

			status = execute(image, keytoolbin);
			if (status != EFI_SUCCESS)
				console_error(L"Failed to execute KeyTool", status);
#if 0
		} else if (option == setup_mode) {
			change_setup_mode(setup_mode_arg);
#endif
		} else if (option == uefi_reboot) {
			transition_to_uefi_menu();
		} else if (option == reboot) {
			int selection;
			selection = console_yes_no((CHAR16 *[]) {
					L"Are you sure you want to reboot?",
					NULL
				});
			if (selection == 1)
				uefi_call_wrapper(RT->ResetSystem, 4,
						  EfiResetWarm,
						  EFI_SUCCESS, 0, NULL);
		} else if (option == exit_moktool) {
			break;
		}
	}
	return EFI_SUCCESS;
}
