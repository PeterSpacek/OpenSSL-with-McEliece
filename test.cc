#include <openssl/engine.h>
#include <stdio.h>
#include <string.h>

int main(int argc, const char* argv[] ) {
    OpenSSL_add_all_algorithms();

    ERR_load_crypto_strings();

    ENGINE_load_dynamic();
    ENGINE *silly = ENGINE_by_id("bpMECS");

    if( silly == NULL )
    {
        printf("Could not Load Oezgan Engine!\n");
        exit(1);
    }
    printf("Oezgan Engine successfully loaded\n");

    int init_res = ENGINE_init(silly);
    printf("Engine name: %s init result : %d \n",ENGINE_get_name(silly), init_res);
    return 0;
}
