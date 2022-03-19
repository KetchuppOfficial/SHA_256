#include "sha_256.h"

int main (void)
{
    const char *str = "Hello, World!";

    char *hash = sha_256 (str, strlen (str));

    free (hash);

    return 0;
}