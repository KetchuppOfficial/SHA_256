#ifndef SHA_256_PUBLIC_INCLUDED
#define SHA_256_PUBLIC_INCLUDED

#include <stdint.h>

char *sha_256 (const char *data, const uint32_t data_len);

#endif