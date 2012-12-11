#ifndef _SHA256_H
#define _SHA256_H

#ifndef uint8
#define uint8  unsigned char
#endif

#ifndef uint32
#define uint32 unsigned long int
#endif

#define SHA256_DIGEST_SIZE 32

typedef struct
{
    uint32 total[2];
    uint32 state[8];
    uint8 buffer[64];
}
sha256_context;

void sha256_starts( sha256_context *ctx );
void sha256_update( sha256_context *ctx, uint8 *input, uint32 length );
void sha256_finish( sha256_context *ctx, uint8 digest[32] );
EFI_STATUS
sha256_get_pecoff_digest_mem(void *buffer, UINTN DataSize,
			     UINT8 hash[SHA256_DIGEST_SIZE]);
void
sha256_StrCat_hash(CHAR16 *str, UINT8 hash[SHA256_DIGEST_SIZE]);
EFI_STATUS
sha256_get_pecoff_digest(EFI_HANDLE device, CHAR16 *name, uint8 digest[SHA256_DIGEST_SIZE]);
#endif /* sha256.h */

