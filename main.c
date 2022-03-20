#include "sha_256.h"

#include <stdlib.h> // for free ()
#include <string.h> // for strlen ()`

int main (void)
{
    const char *str = "Hello, World!";

    char *hash = sha_256 (str, strlen (str));

    free (hash);

    return 0;
}