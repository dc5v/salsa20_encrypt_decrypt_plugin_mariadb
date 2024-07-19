#include <mysql/mysql.h>
#include <sodium.h>
#include <string.h>
#include <stdlib.h>

#define KEY_SIZE 32
#define NONCE_SIZE 24

static int salsa20_encrypt(const unsigned char *key, const unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext);
static int salsa20_decrypt(const unsigned char *key, const unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext);

bool SALSA_ENCRYPT_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
void SALSA_ENCRYPT_deinit(UDF_INIT *initid);
char *SALSA_ENCRYPT(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);

bool SALSA_DECRYPT_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
void SALSA_DECRYPT_deinit(UDF_INIT *initid);
char *SALSA_DECRYPT(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);

static int salsa20_encrypt(const unsigned char *key, const unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext)
{
  unsigned char nonce[NONCE_SIZE];

  randombytes_buf(nonce, sizeof nonce);
  memcpy(ciphertext, nonce, NONCE_SIZE);

  crypto_stream_salsa20_xor(ciphertext + NONCE_SIZE, plaintext, plaintext_len, nonce, key);

  return plaintext_len + NONCE_SIZE;
}

static int salsa20_decrypt(const unsigned char *key, const unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext)
{
  unsigned char nonce[NONCE_SIZE];

  memcpy(nonce, ciphertext, NONCE_SIZE);
  crypto_stream_salsa20_xor(plaintext, ciphertext + NONCE_SIZE, ciphertext_len - NONCE_SIZE, nonce, key);

  return ciphertext_len - NONCE_SIZE;
}

bool SALSA_ENCRYPT_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
  if (args->arg_count != 2 || args->arg_type[0] != STRING_RESULT || args->arg_type[1] != STRING_RESULT)
  {
    strcpy(message, "Expected 2 arguments");
    return 1;
  }

  if (sodium_init() < 0)
  {
    strcpy(message, "Could not initialize sodium library");
    return 1;
  }

  initid->maybe_null = 1;
  return 0;
}

void SALSA_ENCRYPT_deinit(UDF_INIT *initid)
{
}

char *SALSA_ENCRYPT(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
  int plaintext_len = args->lengths[1];
  const unsigned char *key = (const unsigned char *)args->args[0];
  const unsigned char *plaintext = (const unsigned char *)args->args[1];

  int required_len = plaintext_len + NONCE_SIZE;

  if (*length < required_len)
  {
    *is_null = 1;
    return NULL;
  }

  int ciphertext_len = salsa20_encrypt(key, plaintext, plaintext_len, (unsigned char *)result);
  *length = ciphertext_len;

  return result;
}

bool SALSA_DECRYPT_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
  if (args->arg_count != 2 || args->arg_type[0] != STRING_RESULT || args->arg_type[1] != STRING_RESULT)
  {
    strcpy(message, "Expected 2 arguments");
    return 1;
  }

  if (sodium_init() < 0)
  {
    strcpy(message, "Could not initialize sodium library");
    return 1;
  }

  initid->maybe_null = 1;
  return 0;
}

void SALSA_DECRYPT_deinit(UDF_INIT *initid)
{
}

char *SALSA_DECRYPT(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
  int ciphertext_len = args->lengths[1];
  int required_len = ciphertext_len - NONCE_SIZE;
  const unsigned char *key = (const unsigned char *)args->args[0];
  const unsigned char *ciphertext = (const unsigned char *)args->args[1];

  if (*length < required_len)
  {
    *is_null = 1;
    return NULL;
  }

  int plaintext_len = salsa20_decrypt(key, ciphertext, ciphertext_len, (unsigned char *)result);
  *length = plaintext_len;

  return result;
}
