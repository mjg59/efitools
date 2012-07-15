#include <guid.h>
#include <stdio.h>

const char *guid_to_str(EFI_GUID *guid)
{
	static char str[256];

	sprintf(str, "%08x-%04hx-%04hx-%02hhx%02hhx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
		guid->Data1, guid->Data2, guid->Data3,
		guid->Data4[0], guid->Data4[1], guid->Data4[2],
		guid->Data4[3], guid->Data4[4], guid->Data4[5],
		guid->Data4[6], guid->Data4[7]);

	return str;
}

void str_to_guid(const char *str, EFI_GUID *guid)
{
	sscanf(str, "%8x-%4hx-%4hx-%2hhx%2hhx-%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx",
	       &guid->Data1, &guid->Data2, &guid->Data3,
	       guid->Data4, guid->Data4 + 1, guid->Data4 + 2,
	       guid->Data4 + 3, guid->Data4 + 4, guid->Data4 + 5,
	       guid->Data4 + 6, guid->Data4 + 7);
}
