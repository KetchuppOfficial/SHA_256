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

char *sha_complete_hash (const struct SHA_256 *sha)
{
    char *hash = (char *)calloc (HASH_SIZE, sizeof (char));

    for (int i = 0; i < 8; i++)
    {
        *(uint32_t *)(hash + 4 * i) = sha->h[i];
    }

    return hash;
}

uint32_t rotr (uint32_t num, uint32_t shift)
{
    return (num >> shift) | (num << (32 - shift));
}

void sha_recalc_h (struct SHA_256 *sha, const uint32_t chunk_i)
{
    uint32_t a = sha->h[0];
    uint32_t b = sha->h[1];
    uint32_t c = sha->h[2];
    uint32_t d = sha->h[3];
    uint32_t e = sha->h[4];
    uint32_t f = sha->h[5];
    uint32_t g = sha->h[6];
    uint32_t h = sha->h[7];

    for (uint32_t word_i = 0; word_i < 64; word_i++)
    {
        uint32_t S0 = (rotr (a, 2)) ^ (rotr (a, 13)) ^ (rotr (a, 22));
        uint32_t Ma = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + Ma;
        uint32_t S1 = (rotr (e, 6)) ^ (rotr (e, 11)) ^ (rotr (e, 25));
        uint32_t Ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + Ch + k[word_i] + sha->chunks_arr[chunk_i][word_i];

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    sha->h[0] += a;
    sha->h[1] += b;
    sha->h[2] += c;
    sha->h[3] += d;
    sha->h[4] += e;
    sha->h[5] += f;
    sha->h[6] += g;
    sha->h[7] += h;
}

char *sha_hash_calc (struct SHA_256 *sha)
{
    sha->chunks_arr = (uint32_t **)calloc (sha->n_chunks, sizeof (uint32_t *));

    for (uint32_t i = 0; i < sha->n_chunks; i++)
        sha->chunks_arr[i] = (uint32_t *)calloc (64, sizeof (uint32_t));

    for (uint32_t i = 0; i < sha->n_chunks; i++)
    {
        for (uint32_t j = 0; j < 16; j++)
            sha->chunks_arr[i][j] = *(int32_t *)(sha->data + 64 * i + 4 * j);

        for (uint32_t j = 16; j < 64; j++)
        {
            uint32_t S0 = (rotr (sha->chunks_arr[i][j - 15], 7)) ^ (rotr (sha->chunks_arr[i][j - 15], 18)) ^ (sha->chunks_arr[i][j - 15] >> 3);
            uint32_t S1 = (rotr (sha->chunks_arr[i][j - 2], 17)) ^ (rotr (sha->chunks_arr[i][j - 2],  19)) ^ (sha->chunks_arr[i][j - 2] >> 10);
            sha->chunks_arr[i][j] = sha->chunks_arr[i][j - 16] + S0 + sha->chunks_arr[i][j - 7] + S1;
        }

        sha_recalc_h (sha, i);
    }

    char *hash = sha_complete_hash (sha);

    sha_mem_free (sha);

    return hash;
}

void sha_preprocessing (struct SHA_256 *sha, const char *msg, const uint64_t msg_len)
{
    sha->n_chunks = (msg_len / 64 + 1);
    sha->data_len = sha->n_chunks * 64;

    sha->data = (char *)calloc (sha->data_len, sizeof (char));

    memmove (sha->data, msg, msg_len);

    sha->data[msg_len] = 1;

    *(uint64_t *)(sha->data + sha->data_len - 64) = msg_len;
}

void sha_initialize (struct SHA_256 *sha)
{
    /* First 32 bits of the fractional parts 
    of the square roots of the first prime numbers 2..19 */
    sha->h[0] = 0x6a09e667;
    sha->h[1] = 0x6a09e667;
    sha->h[2] = 0xbb67ae85; 
    sha->h[3] = 0x3c6ef372;
    sha->h[4] = 0xa54ff53a;
    sha->h[5] = 0x510e527f; 
    sha->h[6] = 0x9b05688c;
    sha->h[7] = 0x1f83d9ab;
    sha->h[8] = 0x5be0cd19;

    sha->data       = NULL;
    sha->data       = 0;
    sha->chunks_arr = NULL;
    sha->n_chunks   = 0;
}

char *sha_256 (const char *data, const uint32_t data_len)
{
    struct SHA_256 sha = {};

    sha_initialize (&sha);

    sha_preprocessing (&sha, data, data_len);

    return sha_hash_calc (&sha);
}

