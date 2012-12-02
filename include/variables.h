#include <efiauthenticated.h>

EFI_STATUS
CreatePkX509SignatureList (
  IN	UINT8			    *X509Data,
  IN	UINTN			    X509DataSize,
  IN	EFI_GUID		    owner,
  OUT   EFI_SIGNATURE_LIST          **PkCert 
			   );
EFI_STATUS
CreateTimeBasedPayload (
  IN OUT UINTN            *DataSize,
  IN OUT UINT8            **Data
			);
EFI_STATUS
SetSecureVariable(CHAR16 *var, UINT8 *Data, UINTN len, EFI_GUID owner, UINT32 options, int createtimebased);
EFI_STATUS
get_variable(CHAR16 *var, UINT8 **data, UINTN *len, EFI_GUID owner);
EFI_STATUS
find_in_variable_esl(CHAR16* var, EFI_GUID owner, UINT8 *key, UINTN keylen);

#define EFI_OS_INDICATIONS_BOOT_TO_FW_UI 0x0000000000000001

UINT64
GetOSIndications(void);
EFI_STATUS
SETOSIndicationsAndReboot(UINT64 indications);
int
variable_is_secureboot(void);
int
variable_is_setupmode(void);
