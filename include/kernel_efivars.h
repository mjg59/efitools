#include <variables_iterators.h>
void
kernel_variable_init(void);
int
get_variable(const char *var, EFI_GUID *guid, uint32_t *attributes,
	     uint32_t *size, void *buf);
int
get_variable_alloc(const char *var, EFI_GUID *guid, uint32_t *attributes,
		   uint32_t *size, uint8_t **buf);
int
variable_is_setupmode(void);
int
variable_is_secureboot(void);
