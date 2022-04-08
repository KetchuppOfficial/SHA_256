#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

struct SHA_256
{
    uint32_t h[8];
    char     *data;
    uint64_t data_len;
    uint32_t **chunks_arr;
    uint32_t n_chunks;
};

const int HASH_SIZE = 32;

/* First 32 bits of the fractional parts
of the cube roots of the first 64 prime numbers 2..311 */
static const uint32_t k[64] =
{
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5, 
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA, 
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967, 
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070, 
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3, 
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

void sha_mem_free (struct SHA_256 *sha)
{
    free (sha->data);

    for (uint32_t i = 0; i < sha->n_chunks; i++)
        free (sha->chunks_arr[i]);

    free (sha->chunks_arr);
}

uint32_t swap_32bits(uint32_t num)
{
    num = (num & 0xffff0000) >> 16 | (num & 0x0000ffff) << 16;
    num = (num & 0xff00ff00) >>  8 | (num & 0x00ff00ff) <<  8;

    return num;
}

char *sha_complete_hash (struct SHA_256 *sha)
{
    char *hash = (char *)calloc (HASH_SIZE + 1, sizeof (char));

    for (int i = 0; i < 8; i++)
        *(uint32_t *)(hash + 4 * i) = swap_32bits (sha->h[i]);

    return hash;
}

uint32_t rotr (uint32_t num, uint32_t shift)
{
    return (num >> shift) | (num << (32 - shift));
}

void sha_recalc_h (struct SHA_256 *sha, const uint32_t chunk_i)
{
    uint32_t temp_buff[8] = {};
    for (int i = 0; i < 8; i++)
    {
        temp_buff[i] = sha->h[i];
    }

    for (uint32_t word_i = 0; word_i < 64; word_i++)
    {
        uint32_t S0 = rotr (temp_buff[0], 2) ^ rotr (temp_buff[0], 13) ^ rotr (temp_buff[0], 22);
        uint32_t maj = (temp_buff[0] & temp_buff[1]) ^ (temp_buff[0] & temp_buff[2]) ^ (temp_buff[1] & temp_buff[2]);
        uint32_t t2 = S0 + maj;
        uint32_t S1 = rotr (temp_buff[4], 6) ^ rotr (temp_buff[4], 11) ^ rotr (temp_buff[4], 25);
        uint32_t Ch = (temp_buff[4] & temp_buff[5]) ^ (~temp_buff[4] & temp_buff[6]);
        uint32_t t1 = temp_buff[7] + S1 + Ch + k[word_i] + sha->chunks_arr[chunk_i][word_i];

        temp_buff[7] = temp_buff[6];
        temp_buff[6] = temp_buff[5];
        temp_buff[5] = temp_buff[4];
        temp_buff[4] = temp_buff[3] + t1;
        temp_buff[3] = temp_buff[2];
        temp_buff[2] = temp_buff[1];
        temp_buff[1] = temp_buff[0];
        temp_buff[0] = t1 + t2;
    }

    for (int i = 0; i < 8; i++)
    {
        sha->h[i] += temp_buff[i];
    }
}

char *sha_hash_calc (struct SHA_256 *sha)
{
    sha->chunks_arr = (uint32_t **)calloc (sha->n_chunks, sizeof (uint32_t *));

    for (uint32_t chunk_i = 0; chunk_i < sha->n_chunks; chunk_i++)
    {
        sha->chunks_arr[chunk_i] = (uint32_t *)calloc (64, sizeof (uint32_t));
        
        for (uint32_t word_i = 0; word_i < 16; word_i++)
            sha->chunks_arr[chunk_i][word_i] = swap_32bits( *(int32_t *)(sha->data + 64 * chunk_i + 4 * word_i));

        for (uint32_t word_i = 16; word_i < 64; word_i++)
        {
            uint32_t S0 = rotr (sha->chunks_arr[chunk_i][word_i - 15], 7) ^ rotr (sha->chunks_arr[chunk_i][word_i - 15], 18) ^ (sha->chunks_arr[chunk_i][word_i - 15] >> 3);
            uint32_t S1 = rotr (sha->chunks_arr[chunk_i][word_i - 2], 17) ^ rotr (sha->chunks_arr[chunk_i][word_i - 2],  19) ^ (sha->chunks_arr[chunk_i][word_i - 2] >> 10);
            sha->chunks_arr[chunk_i][word_i] = sha->chunks_arr[chunk_i][word_i - 16] + S0 + sha->chunks_arr[chunk_i][word_i - 7] + S1;
        }

        sha_recalc_h (sha, chunk_i);
    }

    char *hash = sha_complete_hash (sha);

    sha_mem_free (sha);

    return hash;
}

uint64_t swap_64bits(uint64_t num)
{
    num = (num & 0xffffffff00000000) >> 32 | (num & 0x00000000ffffffff) << 32;
    num = (num & 0xffff0000ffff0000) >> 16 | (num & 0x0000ffff0000ffff) << 16;
    num = (num & 0xff00ff00ff00ff00) >>  8 | (num & 0x00ff00ff00ff00ff) <<  8;

    return num;
}

void sha_preprocessing (struct SHA_256 *sha, const char *msg)
{
    const uint64_t msg_len = strlen (msg);
    
    uint64_t temp = msg_len * 8 + 1 + 64;
    
    if (temp % 512 == 0)
        sha->n_chunks = temp / 512;
    else
        sha->n_chunks = temp / 512 + 1;
    
    sha->data_len = sha->n_chunks * 64;

    sha->data = (char *)calloc (sha->data_len, sizeof (char));

    memmove (sha->data, msg, msg_len);

    sha->data[msg_len] = 0x80;

    *(uint64_t *)(sha->data + sha->data_len - 8) = swap_64bits (msg_len * 8);
}


void sha_initialize (struct SHA_256 *sha)
{
    /* First 32 bits of the fractional parts 
    of the square roots of the first prime numbers 2..19 */
    sha->h[0] = 0x6a09e667;
    sha->h[1] = 0xbb67ae85; 
    sha->h[2] = 0x3c6ef372;
    sha->h[3] = 0xa54ff53a;
    sha->h[4] = 0x510e527f; 
    sha->h[5] = 0x9b05688c;
    sha->h[6] = 0x1f83d9ab;
    sha->h[7] = 0x5be0cd19;

    sha->data       = NULL;
    sha->data_len   = 0;
    sha->chunks_arr = NULL;
    sha->n_chunks   = 0;
}

void Printf_Sha (const char *hash)
{
    for (int i = 0; i < 8; i++)
    {
        printf ("%08X ", swap_32bits (*(uint32_t *)(hash + 4 * i)));
    }
    printf ("\n");
}

char *sha_256 (const char *data)
{
    struct SHA_256 sha = {};

    sha_initialize (&sha);

    sha_preprocessing (&sha, data);

    return sha_hash_calc (&sha);
}

uint32_t sha_256_32 (const char *data)
{
    char *raw_hash = sha_256 (data);

    uint64_t mask = 0x00000000FFFFFFFF;
    uint32_t hash = *(uint64_t *)(raw_hash + 24) & mask;

    free (raw_hash);

    return hash;
}

uint64_t sha_256_64 (const char *data)
{
    char *raw_hash = sha_256 (data);

    uint64_t hash = *(uint64_t *)(raw_hash + 24);

    free (raw_hash);

    return hash;
}
