#ifndef SHA_256_PUBLIC_INCLUDED
#define SHA_256_PUBLIC_INCLUDED

#include <inttypes.h>

char     *sha_256   (const char *data);
uint32_t sha_256_32 (const char *data);
uint64_t sha_256_64 (const char *data);

void Printf_Sha (const char *hash);

#endif