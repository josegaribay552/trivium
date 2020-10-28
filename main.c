/*////////////////////////////////////////////////////////
Programa principal del trivum
alumno:jose antonio garibay chavez 
critpografia 
especialidad en sistemas embebidos
*//////////////////////////////////////////////////////

// PARTE PARA LOS INCLUDE E INCLUSION DE LIBRERIAS

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stddef.h>
#include "trivium.c"

#define TEXTOPLANO 1024

//PROGRAMA PRINCIPAL 

int main()
{
    char input[TEXTOPLANO] = "anita lava la tina";
    ECRYPT_ctx ctx;
    u8 *key, *IV, *textocifrado, *result;

    key = (u8 *)calloc((size_t)ECRYPT_MAXKEYSIZE/8, sizeof(u8));
    IV = (u8 *)calloc((size_t)ECRYPT_MAXIVSIZE/8, sizeof(u8));

    printf("Encriptando trivium [%s] usando llave random de tamaño %d y %d bit IV:\n", input, ECRYPT_MAXKEYSIZE, ECRYPT_MAXIVSIZE);

    ECRYPT_init();
    ECRYPT_keysetup(&ctx, key, ECRYPT_MAXKEYSIZE, ECRYPT_MAXIVSIZE);
    ECRYPT_ivsetup(&ctx, IV);

    textocifrado = (u8 *)calloc((size_t)TEXTOPLANO, sizeof(u8));
    printf("mensaje encriptado trivium: [%i] \n",textocifrado);
    

    ECRYPT_encrypt_bytes(&ctx, input, textocifrado, TEXTOPLANO);

    result = (u8 *)calloc((size_t)TEXTOPLANO, sizeof(u8));

    ECRYPT_ivsetup(&ctx, IV); 
    ECRYPT_decrypt_bytes(&ctx, textocifrado, result, TEXTOPLANO);
    printf("Desencriptando mensaje trivium: [%s]\n", result);

    return 0;
}

