/* trivium */       
//#include "ecrypt-portable.h" 
/* 
 * REFERENCIA DE IMPLEMENTACION DE ALGORITMO TRIVIUM
 */

/* ------------------------------------------------------------------------- */
/* ecrypt-portable.h */

/*
 *Las conversiones que se realizan abajo estan implementadas como macros 
 * para cuestiones de practicidad en este caso usamos arquitectura de 64 bits 
 * en compilador de 32 bits
 */

#include "ecrypt-config.h"

/* ------------------------------------------------------------------------- */

/* DEFINICIONES DE TIPO DE DATOS PARA PORTABILIDAD EN ESTE CASO PARA SISTEMA DE 32 BITS Y FRAGMENTOS DE 8 BITS
 * Se definieron lo siguientes tipos de datos:
 *
 * u8:  unsigned integer type, al menos 8 bits
 * u32: unsigned integer type, al menos 32 bits
 * 
 * s8,s32-> son las versiones con signos de sus  
 * contrapartes de u8, u32
 *
 * ESTAS MACROS SE USAN PARA DEFINIR TIPOS DE DATOS DESDE EL MAS MINIMO:
 * 
 * Nota:  PARA HABILITAR TIPOS DE BITS DE 64 SOBRE 
 * COMPIALDORES DE 32 SERA NECESARIO CAMBIAR DEL ISO C90 AL ISO C99 
 * EJEMPLO:
 * C99 mode (e.g., gcc -std=c99).
 */

#ifdef I8T
typedef signed I8T s8;
typedef unsigned I8T u8;
#endif

#ifdef I32T
typedef signed I32T s32;
typedef unsigned I32T u32;
#endif

/*
 * The following macros are used to obtain exact-width results.
 */

#define U8V(v) ((u8)(v) & U8C(0xFF))
/* ------------------------------------------------------------------------- */
/* ------------------------------------------------------------------------- */

#ifdef ECRYPT_LITTLE_ENDIAN
#define U32TO32_LITTLE(v) (v)
#endif


/*
 * The following macros load words from an array of bytes with
 * different types of endianness, and vice versa.
 */

#define ECRYPT_DEFAULT_BTOW

#if (!defined(ECRYPT_UNKNOWN) && defined(ECRYPT_I8T_IS_BYTE))

#define U8TO32_LITTLE(p) U32TO32_LITTLE(((u32*)(p))[0])

#define U32TO8_LITTLE(p, v) (((u32*)(p))[0] = U32TO32_LITTLE(v))

#else

#define U8TO32_LITTLE(p) \
  (((u32)((p)[0])      ) | \
   ((u32)((p)[1]) <<  8) | \
   ((u32)((p)[2]) << 16) | \
   ((u32)((p)[3]) << 24))

#endif


//definicion de la estructura de ecrypt-sync.h
/* Estructura de datos */
/* 
 * ECRYPT_ctx es la estructura que contiene la representacion del estado interno del cifrador
 *  
 */
typedef struct
{
  u32 keylen;
  u32 ivlen;
  u8 s[40];
  u8 key[10];
} ECRYPT_ctx;
/* ------------------------------------------------------------------------- */
/* ------------------------------------------------------------------------- */
/*
 *-----------------------------------------------------------------------------
 * NOTA: ESTA ES LA PARTE QUE REALIZA LAS OPERACIONES PRINCIPALES DEL ALGORTIMO TRIVIUM 
 * ----------------------------------------------------------------------------
 */

//se definen deplazamientos de bits de los estados 32 bits//
//donde t1 son los registros de despalzamiento decordado 1 bit cada registro

//desplazamiento,rotacion, actualizacion y guaradado de variables en formao endian
//tambien genera los keystreams zt=t1+t2+t3;

#define S00(a, b) ((S(a, 1) << ( 32 - (b))))
#define S32(a, b) ((S(a, 2) << ( 64 - (b))) | (S(a, 1) >> ((b) - 32)))
#define S64(a, b) ((S(a, 3) << ( 96 - (b))) | (S(a, 2) >> ((b) - 64)))
#define S96(a, b) ((S(a, 4) << (128 - (b))) | (S(a, 3) >> ((b) - 96)))

//define update tiene los registros de desplazamiento de diferente longitud
//y la generacion de los keystream
//asi como actualiza los valores de cada regitro en la nueva iteracion

#define ACTUALIZAR()                                                             \
  do {                                                                       \
    T(1) = S64(1,  66) ^ S64(1,  93);                                        \
    T(2) = S64(2,  69) ^ S64(2,  84);                                        \
    T(3) = S64(3,  66) ^ S96(3, 111);                                        \
                                                                             \
    Z(T(1) ^ T(2) ^ T(3));                                                   \
                                                                             \
    T(1) ^= (S64(1,  91) & S64(1,  92)) ^ S64(2,  78);                       \
    T(2) ^= (S64(2,  82) & S64(2,  83)) ^ S64(3,  87);                       \
    T(3) ^= (S96(3, 109) & S96(3, 110)) ^ S64(1,  69);                       \
  } while (0)

#define ROTACION()                                                             \
  do {                                                                       \
    S(1, 3) = S(1, 2); S(1, 2) = S(1, 1); S(1, 1) = T(3);                    \
    S(2, 3) = S(2, 2); S(2, 2) = S(2, 1); S(2, 1) = T(1);                    \
    S(3, 4) = S(3, 3); S(3, 3) = S(3, 2); S(3, 2) = S(3, 1); S(3, 1) = T(2); \
  } while (0)

#define ASIGNAR(s)                                                              \
  do {                                                                       \
    S(1, 1) = U8TO32_LITTLE((s) +  0);                                       \
    S(1, 2) = U8TO32_LITTLE((s) +  4);                                       \
    S(1, 3) = U8TO32_LITTLE((s) +  8);                                       \
                                                                             \
    S(2, 1) = U8TO32_LITTLE((s) + 12);                                       \
    S(2, 2) = U8TO32_LITTLE((s) + 16);                                       \
    S(2, 3) = U8TO32_LITTLE((s) + 20);                                       \
                                                                             \
    S(3, 1) = U8TO32_LITTLE((s) + 24);                                       \
    S(3, 2) = U8TO32_LITTLE((s) + 28);                                       \
    S(3, 3) = U8TO32_LITTLE((s) + 32);                                       \
    S(3, 4) = U8TO32_LITTLE((s) + 36);                                       \
  } while (0)

#define ALMACENAR(s)                                                            \
  do {                                                                      \
    U32TO8_LITTLE((s) +  0, S(1, 1));                                       \
    U32TO8_LITTLE((s) +  4, S(1, 2));                                       \
    U32TO8_LITTLE((s) +  8, S(1, 3));                                       \
                                                                            \
    U32TO8_LITTLE((s) + 12, S(2, 1));                                       \
    U32TO8_LITTLE((s) + 16, S(2, 2));                                       \
    U32TO8_LITTLE((s) + 20, S(2, 3));                                       \
                                                                            \
    U32TO8_LITTLE((s) + 24, S(3, 1));                                       \
    U32TO8_LITTLE((s) + 28, S(3, 2));                                       \
    U32TO8_LITTLE((s) + 32, S(3, 3));                                       \
    U32TO8_LITTLE((s) + 36, S(3, 4));                                       \
  } while (0)

/* ------------------------------------------------------------------------- */

void ECRYPT_init(void)
{ }

/* ------------------------------------------------------------------------- */

void ECRYPT_keysetup(
  ECRYPT_ctx* ctx, 
  const u8* key, 
  u32 keysize,
  u32 ivsize)
{
  u32 i;

  ctx->keylen = (keysize + 7) / 8;
  ctx->ivlen = (ivsize + 7) / 8;

  for (i = 0; i < ctx->keylen; ++i)
    ctx->key[i] = key[i];
}

/* ------------------------------------------------------------------------- */

#define S(a, n) (s##a##n)
#define T(a) (t##a)

void ECRYPT_ivsetup(
  ECRYPT_ctx* ctx, 
  const u8* iv)
{
  u32 i;

  u32 s11, s12, s13;
  u32 s21, s22, s23;
  u32 s31, s32, s33, s34;

  for (i = 0; i < ctx->keylen; ++i)
    ctx->s[i] = ctx->key[i];

  for (i = ctx->keylen; i < 12; ++i)
    ctx->s[i] = 0;

  for (i = 0; i < ctx->ivlen; ++i)
    ctx->s[i + 12] = iv[i];

  for (i = ctx->ivlen; i < 12; ++i)
    ctx->s[i + 12] = 0;

  for (i = 0; i < 13; ++i)
    ctx->s[i + 24] = 0;

  ctx->s[13 + 24] = 0x70;

  ASIGNAR(ctx->s);

#define Z(w)

  for (i = 0; i < 4 * 9; ++i)
    {
      u32 t1, t2, t3;
      
      ACTUALIZAR();
      ROTACION();
    }

  ALMACENAR(ctx->s);
}
//ecrypt parte //
/* ------------------------------------------------------------------------- */

/* 
 * Header file for synchronous stream ciphers without authentication
 * mechanism.
 */
/* ------------------------------------------------------------------------- */
/* PARAMETROS DE CIFRADO */

/*
 * ESPECIFICA UN TAMAÑO PARA LA CLAVE Y IV QUE SOPORTARA EL CIFRADOR EN BITS
 *
 */
#define ENCRYPT_MAXKEYTAM 80                  /* [SE PUEDE MODIFICAR] */
#define ECRYPT_KEYSIZE(i) (80 + (i)*32)       /* [SE PUEDE MODIFICAR] */
#define ENCRYPT_MAXIVTAM 80                   /* [SE PUEDE MODIFICAR] */
#define ECRYPT_IVSIZE(i) (32 + (i)*16)        /* [SE PUEDE MODIFICAR] */
/* ------------------------------------------------------------------------- */
/* ------------------------------------------------------------------------- */

/* funciones obligatorias */

/* 
 * inicializacion de la clave y mensaje independientemente 
 * esta funcion sera llamada una vez que el programa inicie.
 */
void ECRYPT_init(void);

/*
 * Key setup.es la responsabilidad del usuario seleccionar el tamaño de la clave o keysize y el iv size de  
 * keysize and ivsize de el conjunto de valores especificados arriba que son soportados
 * 
 */
void ECRYPT_keysetup(
  ECRYPT_ctx* ctx, 
  const u8* key, 
  u32 keysize,                /* Key tamaño en bits. */ 
  u32 ivsize);                /* IV tamaño en bits. */ 

/*
 * 
 * IV setup.Despues de llamar la funcion anterior el usuario podra llamar
 * la funcion de inicializacion de IV oECRYPT_ivsetup() varias veces 
 * para encriptar o desencriptar mensajes con la mism llave pero diferente IV
 * 
 */
void ECRYPT_ivsetup(
  ECRYPT_ctx* ctx, 
  const u8* iv);

/*
 * Encriptacion/desencriptacion  de mensajes de longitud arbitraria.
 *
 * La funcion ECRYPT_encrypt_bytes() encadena cadenas de bytes de longitud arbitraria
 *  
 * El usuario tiene permitido hacer multiples llamadas pero no si ya se ha invocado a 
 * ECRYPT_encrypt_bytes() claro a menos que inicie un nuevo mensaje.
 * 
 */

/*
 * By default ECRYPT_encrypt_bytes() and ECRYPT_decrypt_bytes() are
 * defined as macros which redirect the call to a single function
 * ECRYPT_process_bytes(). If you want to provide separate encryption
 * and decryption functions, please undef
 * ECRYPT_HAS_SINGLE_BYTE_FUNCTION.
 */
#define ECRYPT_HAS_SINGLE_BYTE_FUNCTION       /* [edit] */
#ifdef ECRYPT_HAS_SINGLE_BYTE_FUNCTION

#define ECRYPT_encrypt_bytes(ctx, plaintext, ciphertext, msglen)   \
ECRYPT_process_bytes(0, ctx, plaintext, ciphertext, msglen)

#define ECRYPT_decrypt_bytes(ctx, ciphertext, plaintext, msglen)   \
ECRYPT_process_bytes(1, ctx, ciphertext, plaintext, msglen)

void ECRYPT_process_bytes(
  int action,                 /* 0 = ENCRIPTAR; 1 = DESENCRIPTAR; */
  ECRYPT_ctx* ctx, 
  const u8* input, 
  u8* output, 
  u32 msglen);                /* longitud del mensaje en bytes. */ 

#else

void ECRYPT_encrypt_bytes(
  ECRYPT_ctx* ctx, 
  const u8* plaintext, 
  u8* ciphertext, 
  u32 msglen);                /*longitud del mensaje en bytes. */ 

void ECRYPT_decrypt_bytes(
  ECRYPT_ctx* ctx, 
  const u8* ciphertext, 
  u8* plaintext, 
  u32 msglen);                /* longitud del mensaje en bytes. */ 

#endif

//ecrypt-sync parte //
//funcion de encriptacion de bytes
void ECRYPT_process_bytes(
  int action,
  ECRYPT_ctx* ctx, 
  const u8* entrada, 
  u8* salida, 
  u32 msglong)
{
  u32 i;

  u32 s11, s12, s13;
  u32 s21, s22, s23;
  u32 s31, s32, s33, s34;

  u32 z;

  ASIGNAR(ctx->s);

#undef Z
#define Z(w) (U32TO8_LITTLE(salida + 4 * i, U8TO32_LITTLE(entrada + 4 * i) ^ w))

  for (i = 0; i < msglong / 4; ++i)
    {
      u32 t1, t2, t3;
      
      ACTUALIZAR();
      ROTACION();
    }

#undef Z
#define Z(w) (z = w)

  i *= 4;

  if (i < msglong)
    {
      u32 t1, t2, t3;
      
      ACTUALIZAR();
      ROTACION();

      for ( ; i < msglong; ++i, z >>= 8)
	salida[i] = entrada[i] ^ U8V(z); 
    }

  ALMACENAR(ctx->s);
}

/* ------------------------------------------------------------------------- */
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


#define TEXTOPLANO 1024

//PROGRAMA PRINCIPAL 

int main()
{
    char input[TEXTOPLANO] = "MARTA TIENE UN MARCAPASOS";
    ECRYPT_ctx ctx;
    u8 *key, *IV, *textocifrado, *result;

    key = (u8 *)calloc((size_t)ENCRYPT_MAXKEYTAM/8, sizeof(u8));
    IV = (u8 *)calloc((size_t)ENCRYPT_MAXIVTAM/8, sizeof(u8));

    printf("Encriptando trivium [%s] usando llave random de tamaño %d y %d bit IV:\n", input, ENCRYPT_MAXKEYTAM, ENCRYPT_MAXIVTAM);

    ECRYPT_init();
    ECRYPT_keysetup(&ctx, key, ENCRYPT_MAXKEYTAM, ENCRYPT_MAXIVTAM);
    ECRYPT_ivsetup(&ctx, IV);

    textocifrado = (u8 *)calloc((size_t)TEXTOPLANO, sizeof(u8));
    printf("mensaje encriptado en trivium: [%d] \n",textocifrado);
    
    ECRYPT_encrypt_bytes(&ctx, input, textocifrado, TEXTOPLANO);

    result = (u8 *)calloc((size_t)TEXTOPLANO, sizeof(u8));

    ECRYPT_ivsetup(&ctx, IV); 
    ECRYPT_decrypt_bytes(&ctx, textocifrado, result, TEXTOPLANO);
    printf("Desencriptando mensaje en trivium: [%s]\n", result);

    return 0;
}

