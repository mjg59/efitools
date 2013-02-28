#include <variables_iterators.h>
#include <sha256.h>
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
int
set_variable(const char *var, EFI_GUID *guid, uint32_t attributes,
	     uint32_t size, void *buf);
int
set_variable_esl(const char *var, EFI_GUID *guid, uint32_t attributes,
		 uint32_t size, void *buf);
int
set_variable_hash(const char *var, EFI_GUID *owner, uint32_t attributes,
		  uint8_t hash[SHA256_DIGEST_SIZE]);
uint8_t *
hash_to_esl(EFI_GUID *owner, int *len,
	    uint8_t hash[SHA256_DIGEST_SIZE]);
