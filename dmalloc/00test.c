
#include <stdio.h>
#include <string.h>
const char* canary_value = "NaIroBi";


int main(int argc, char const *argv[])
{
    size_t very_large_nmemb = (size_t) -1 / 8 + 2;
    printf("Canary: %zu\n", (very_large_nmemb * 16));
    return 0;
}

