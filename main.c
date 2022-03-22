#include "sha_256.h"

#include <stdlib.h> // for free ()

int main (void)
{
    const char *test_str_1 = "The quick brown fox jumps over the lazy dog";
    const char *test_str_2 = "";

    char *hash_1 = sha_256 (test_str_1);
    Printf_Sha (hash_1);
    free (hash_1);

    char *hash_2 = sha_256 (test_str_2);
    Printf_Sha (hash_2);
    free (hash_2);

    return 0;
}