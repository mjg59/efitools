/*
 * Copyright 2012 <James.Bottomley@HansenPartnership.com>
 *
 * see COPYING file
 *
 * Install and remove a platform security2 override policy
 */

#include <efi.h>
#include <efilib.h>

#include <guid.h>
#include <sha256.h>
#include <variables.h>
#include <errors.h>

#include <security_policy.h>

/*
 * See the UEFI Platform Initialization manual (Vol2: DXE) for this
 */
struct _EFI_SECURITY2_PROTOCOL;
struct _EFI_DEVICE_PATH_PROTOCOL;
typedef struct _EFI_SECURITY2_PROTOCOL EFI_SECURITY2_PROTOCOL;
typedef struct _EFI_DEVICE_PATH_PROTOCOL EFI_DEVICE_PATH_PROTOCOL;

typedef EFI_STATUS (EFIAPI *EFI_SECURITY2_FILE_AUTHENTICATION) (
			const EFI_SECURITY2_PROTOCOL *This,
			const EFI_DEVICE_PATH_PROTOCOL *DevicePath,
			VOID *FileBuffer,
			UINTN FileSize,
			BOOLEAN	BootPolicy
								     );

struct _EFI_SECURITY2_PROTOCOL {
	EFI_SECURITY2_FILE_AUTHENTICATION FileAuthentication;
};

static UINT8 *security_policy_esl = NULL;
static UINTN security_policy_esl_len;

static EFI_STATUS
security_policy_check_mok(void *data, UINTN len)
{
	EFI_STATUS status;
	UINT8 hash[SHA256_DIGEST_SIZE];
	UINT32 attr;
	UINT8 *VarData;
	UINTN VarLen;

	/* first check is MokSBState.  If we're in insecure mode, boot
	 * anyway regardless of dbx contents */
	status = get_variable_attr(L"MokSBState", &VarData, &VarLen,
				   MOK_OWNER, &attr);
	if (status == EFI_SUCCESS) {
		UINT8 MokSBState = VarData[0];

		FreePool(VarData);
		if ((attr & EFI_VARIABLE_RUNTIME_ACCESS) == 0
		    && MokSBState)
			return EFI_SUCCESS;
	}

	status = sha256_get_pecoff_digest_mem(data, len, hash);
	if (status != EFI_SUCCESS)
		return status;

	if (find_in_variable_esl(L"dbx", SIG_DB, hash, SHA256_DIGEST_SIZE)
	    == EFI_SUCCESS)
		/* MOK list cannot override dbx */
		goto check_tmplist;

	status = get_variable_attr(L"MokList", &VarData, &VarLen, MOK_OWNER,
				   &attr);
	if (status != EFI_SUCCESS)
		goto check_tmplist;

	FreePool(VarData);

	if (attr & EFI_VARIABLE_RUNTIME_ACCESS)
		goto check_tmplist;

	if (find_in_variable_esl(L"MokList", MOK_OWNER, hash, SHA256_DIGEST_SIZE) == EFI_SUCCESS)
		return EFI_SUCCESS;

 check_tmplist:
	if (security_policy_esl
	    && find_in_esl(security_policy_esl, security_policy_esl_len, hash,
			   SHA256_DIGEST_SIZE) == EFI_SUCCESS)
		return EFI_SUCCESS;

	return EFI_SECURITY_VIOLATION;
}

static EFI_SECURITY2_FILE_AUTHENTICATION es2fa = NULL;

/* Nasty: ELF and EFI have different calling conventions.  Here is the map for
 * calling ELF -> EFI
 *
 *   1) rdi -> rcx (32 saved)
 *   2) rsi -> rdx (32 saved)
 *   3) rdx -> r8 ( 32 saved)
 *   4) rcx -> r9 (32 saved)
 *   5) r8 -> 32(%rsp) (48 saved)
 *   6) r9 -> 40(%rsp) (48 saved)
 *   7) pad+0(%rsp) -> 48(%rsp) (64 saved)
 *   8) pad+8(%rsp) -> 56(%rsp) (64 saved)
 *   9) pad+16(%rsp) -> 64(%rsp) (80 saved)
 *  10) pad+24(%rsp) -> 72(%rsp) (80 saved)
 *  11) pad+32(%rsp) -> 80(%rsp) (96 saved)

 *
 * So for a five argument callback, the map is ignore the first two arguments
 * and then map (EFI -> ELF) assuming pad = 0.
 *
 * ARG4  -> ARG1
 * ARG3  -> ARG2
 * ARG5  -> ARG3
 * ARG6  -> ARG4
 * ARG11 -> ARG5
 */

static UINT64 security_policy_authentication (
	UINT64 ARG1, UINT64 ARG2, UINT64 ARG3, UINT64 ARG4, UINT64 ARG5,
	UINT64 ARG6, UINT64 ARG7, UINT64 ARG8, UINT64 ARG9, UINT64 ARG10,
	UINT32 ARG11)
{
	EFI_STATUS status;
	const EFI_SECURITY2_PROTOCOL *This = (void *)ARG4;
	const EFI_DEVICE_PATH_PROTOCOL *DevicePath = (void *)ARG3;
	VOID *FileBuffer = (void *)ARG5;
	UINTN FileSize = ARG6;
	BOOLEAN	BootPolicy = ARG11;

	status = security_policy_check_mok(FileBuffer, FileSize);

	Print(L"IN SECURITY VALIDATION MOK on %lx,%lx,%lx,%ld) returns %d\n", This,DevicePath,FileBuffer,FileSize, status);
	console_get_keystroke();

	if (status == EFI_SUCCESS)
		return status;

	/* chain previous policy (UEFI security validation) */
	status = uefi_call_wrapper(es2fa, 5, This, DevicePath, FileBuffer,
				   FileSize, BootPolicy);

	Print(L"Previous Security Policy returns %d\n", status);
	console_get_keystroke();

	return status;
}

EFI_STATUS
security_policy_install(void)
{
	EFI_SECURITY2_PROTOCOL *security2_protocol;
	EFI_STATUS status;

	if (es2fa)
		/* Already Installed */
		return EFI_ALREADY_STARTED;

	status = uefi_call_wrapper(BS->LocateProtocol, 3,
				   &SECURITY2_PROTOCOL_GUID, NULL,
				   &security2_protocol);
	if (status != EFI_SUCCESS)
		return status;

	Print(L"SECURITY2 PROTOCOL returns %lx, new func is %lx\n", security2_protocol, security_policy_authentication);

	es2fa = security2_protocol->FileAuthentication;
	security2_protocol->FileAuthentication = 
		(EFI_SECURITY2_FILE_AUTHENTICATION)security_policy_authentication;

	return EFI_SUCCESS;
}

EFI_STATUS
security_policy_uninstall(void)
{
	EFI_SECURITY2_PROTOCOL *security2_protocol;
	EFI_STATUS status;

	if (!es2fa)
		/* Not Installed */
		return EFI_NOT_STARTED;

	status = uefi_call_wrapper(BS->LocateProtocol, 3,
				   &SECURITY2_PROTOCOL_GUID, NULL,
				   &security2_protocol);

	if (status != EFI_SUCCESS)
		return status;

	security2_protocol->FileAuthentication = es2fa;
	es2fa = NULL;

	return EFI_SUCCESS;
}

void
security_protocol_set_hashes(unsigned char *esl, int len)
{
	security_policy_esl = esl;
	security_policy_esl_len = len;
}
