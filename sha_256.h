#ifndef SHA_256_INCLUDED
#define SHA_256_INCLUDED

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

struct SHA_256
{
    uint32_t h[8];
    char     *data;
    uint64_t data_len;
    uint32_t **chunks_arr;
    uint32_t n_chunks;
};

char     *sha_256           (const char *data, const uint32_t data_len);
void     sha_initialize     (struct SHA_256 *sha);
void     sha_preprocessing  (struct SHA_256 *sha, const char *msg, const uint64_t msg_len);
char     *sha_hash_calc     (struct SHA_256 *sha);
void     sha_recalc_h       (struct SHA_256 *sha, const uint32_t chunk_i);
uint32_t rotr               (uint32_t num, uint32_t shift);
char     *sha_complete_hash (const struct SHA_256 *sha);
void     sha_mem_free       (struct SHA_256 *sha);

#endif