#include <mysql/mysql.h>
#include <sodium.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define KEY_SIZE 32
#define NONCE_SIZE 24

static int salsa20_encrypt(const unsigned char *key, const unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext);
static int salsa20_decrypt(const unsigned char *key, const unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext);
static char *gen_base64(const unsigned char *input, int length);
static char *gen_hex(const unsigned char *input, int length);

bool SALSA_ENCRYPT_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
void SALSA_ENCRYPT_deinit(UDF_INIT *initid);
char *SALSA_ENCRYPT(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);

bool SALSA_DECRYPT_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
void SALSA_DECRYPT_deinit(UDF_INIT *initid);
char *SALSA_DECRYPT(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);

static int salsa20_encrypt(const unsigned char *key, const unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext)
{
  unsigned char nonce[NONCE_SIZE];

  randombytes_buf(nonce, sizeof(nonce));

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

static char *gen_base64(const unsigned char *input, int length)
{
  int output_length = sodium_base64_encoded_len(length, sodium_base64_VARIANT_ORIGINAL);
  char *output = (char *)malloc(output_length);

  if (output == NULL)
  {
    return NULL;
  }

  sodium_bin2base64(output, output_length, input, length, sodium_base64_VARIANT_ORIGINAL);

  return output;
}

static char *gen_hex(const unsigned char *input, int length)
{
  char *output = (char *)malloc(length * 2 + 1);

  if (output == NULL)
  {
    return NULL;
  }

  sodium_bin2hex(output, length * 2 + 1, input, length);

  return output;
}

bool SALSA_ENCRYPT_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
  if (args->arg_count < 2 || args->arg_count > 3 || args->arg_type[0] != STRING_RESULT || args->arg_type[1] != STRING_RESULT || (args->arg_count == 3 && args->arg_type[2] != STRING_RESULT))
  {
    strcpy(message, "Called without required arguments. args:(key, text, ['base64' | 'hex' | 'binary' | 'blob' ])");
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
  const unsigned char *key = (const unsigned char *)args->args[0];
  const unsigned char *text = (const unsigned char *)args->args[1];
  int text_len = args->lengths[1];

  const char *arg_format = args->arg_count == 3 ? (const char *)args->args[2] : "blob";
  int required_len = text_len + NONCE_SIZE;
  unsigned char *cipher_text = (unsigned char *)malloc(required_len);

  if (cipher_text == NULL)
  {
    *is_null = 1;
    return NULL;
  }

  int ciphertext_len = salsa20_encrypt(key, text, text_len, cipher_text);

  char *result = NULL;

  /* base64 */
  if (strcmp(arg_format, "base64") == 0)
  {
    result = gen_base64(cipher_text, ciphertext_len);

    if (result == NULL)
    {
      free(cipher_text);
      *is_null = 1;

      return NULL;
    }

    strcpy(result, result);
    *length = strlen(result);

    free(result);
  }
  /* hex */
  else if (strcmp(arg_format, "hex") == 0)
  {
    result = gen_hex(cipher_text, ciphertext_len);

    if (result == NULL)
    {
      free(cipher_text);
      *is_null = 1;

      return NULL;
    }

    strcpy(result, result);
    *length = strlen(result);

    free(result);
  }
  /* binary */
  else if (strcmp(arg_format, "binary") == 0)
  {
    memcpy(result, cipher_text, ciphertext_len);
    *length = ciphertext_len;
  }
  /* blob */
  else
  {
    memcpy(result, cipher_text, ciphertext_len);
    *length = ciphertext_len;
  }

  free(cipher_text);

  return result;
}

bool SALSA_DECRYPT_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
  if (args->arg_count != 2 || args->arg_type[0] != STRING_RESULT || args->arg_type[1] != STRING_RESULT)
  {
    strcpy(message, "Called without required arguments. args:(key, encrypted_var)");
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
  const unsigned char *key = (const unsigned char *)args->args[0];
  const unsigned char *cipher_text = (const unsigned char *)args->args[1];

  int cipher_text_len = args->lengths[1];
  int required_len = cipher_text_len - NONCE_SIZE;

  if (*length < required_len)
  {
    *is_null = 1;
    return NULL;
  }

  int text_len = salsa20_decrypt(key, cipher_text, cipher_text_len, (unsigned char *)result);
  *length = text_len;

  return result;
}
