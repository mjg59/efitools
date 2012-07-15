#include <efi.h>

const char *guid_to_str(EFI_GUID *guid);
void str_to_guid(const char *str, EFI_GUID *guid);
