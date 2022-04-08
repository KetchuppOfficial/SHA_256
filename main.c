#include "sha_256.h"

#include <stdlib.h> // for free ()
#include <stdio.h>  // for printf ()

int main (void)
{
    const char *test_str = "It will be legen ... wait for it ... dary! Legendary!";

    char *hash_1 = sha_256 (test_str);
    Printf_Sha (hash_1);

    printf ("uint32_t hash = %u\n", sha_256_32 (test_str));
    printf ("uint64_t hash = %lu\n", sha_256_64 (test_str));

    free (hash_1);

    return 0;
}
