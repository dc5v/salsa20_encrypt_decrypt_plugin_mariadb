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
static char *gen_binary(const unsigned char *input, int length);
static int from_base64(const char *input, unsigned char **output, int *output_len);
static int from_hex(const char *input, unsigned char **output, int *output_len);
static int from_binary(const char *input, unsigned char **output, int *output_len);
static int detect_format(const char *input);

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
  char *output = (char*) malloc(output_length);

  if (output == NULL)
  {
    return NULL;
  }

  sodium_bin2base64(output, output_length, input, length, sodium_base64_VARIANT_ORIGINAL);

  return output;
}

static char *gen_hex(const unsigned char *input, int length)
{
  char *output = (char*) malloc(length * 2 + 1);

  if (output == NULL)
  {
    return NULL;
  }

  sodium_bin2hex(output, length * 2 + 1, input, length);

  return output;
}

static char *gen_binary(const unsigned char *input, int length)
{
  // 8 bit
  char *output = (char*) malloc(length * 8 + 1);

  if (output == NULL)
  {
    return NULL;
  }

  for (int i = 0; i < length; i++)
  {
    for (int j = 0; j < 8; j++)
    {
      output[i * 8 + j] = (input[i] & (1 << (7 - j))) ? '1' : '0';
    }
  }

  output[length * 8] = '\0';

  return output;
}

static int from_base64(const char *input, unsigned char **output, int *output_len)
{
  size_t input_len = strlen(input);
  *output = (unsigned char *)malloc(input_len);

  if (*output == NULL)
  {
    return -1;
  }

  if (sodium_base642bin(*output, input_len, input, input_len, NULL, (size_t *)output_len, NULL, sodium_base64_VARIANT_ORIGINAL) != 0)
  {
    free(*output);
    *output = NULL;

    return -1;
  }

  return 0;
}

static int from_hex(const char *input, unsigned char **output, int *output_len)
{
  size_t input_len = strlen(input);

  *output = (unsigned char *)malloc(input_len / 2);

  if (*output == NULL)
  {
    return -1;
  }

  if (sodium_hex2bin(*output, input_len / 2, input, input_len, NULL, (size_t *)output_len, NULL) != 0)
  {
    free(*output);
    *output = NULL;

    return -1;
  }

  return 0;
}

static int from_binary(const char *input, unsigned char **output, int *output_len)
{
  size_t input_len = strlen(input);

  if (input_len % 8 != 0)
  {
    return -1;
  }

  *output_len = input_len / 8;
  *output = (unsigned char *)malloc(*output_len);

  if (*output == NULL)
  {
    return -1;
  }

  for (int i = 0; i < *output_len; i++)
  {
    (*output)[i] = 0;

    for (int j = 0; j < 8; j++)
    {
      if (input[i * 8 + j] == '1')
      {
        (*output)[i] |= (1 << (7 - j));
      }
      else if (input[i * 8 + j] != '0')
      {
        free(*output); *output = NULL; return -1;
      }
    }
  }

  return 0;
}

static int detect_format(const char *input)
{
  size_t len = strlen(input);

  // base64
  if (len % 4 == 0 && strspn(input, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") == len)
  {
    return 1;
  }
  // hex
  else if (len % 2 == 0 && strspn(input, "0123456789abcdefABCDEF") == len)
  {
    return 2;
  }
  // binary
  else if (strspn(input, "01") == len)
  {
    return 3;
  }
  // blob
  else
  {
    return 0;
  }
}

bool SALSA_ENCRYPT_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
  if (args->arg_count < 2 || args->arg_count > 3 ||
      args->arg_type[0] != STRING_RESULT || args->arg_type[1] != STRING_RESULT ||
      (args->arg_count == 3 && args->arg_type[2] != STRING_RESULT))
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
  const unsigned char *key = (const unsigned char *) args->args[0];
  const unsigned char *text = (const unsigned char *) args->args[1];
  int text_len = args->lengths[1];

  const char *arg_format = args->arg_count == 3 ? (const char *) args->args[2] : "blob";
  int required_len = text_len + NONCE_SIZE;
  unsigned char *cipher_text = (unsigned char *) malloc(required_len);

  if (cipher_text == NULL)
  {
    *is_null = 1;
    return NULL;
  }

  int ciphertext_len = salsa20_encrypt(key, text, text_len, cipher_text);
  char *output = NULL;

  /* encode - base64 */
  if (strcmp(arg_format, "base64") == 0)
  {
    output = gen_base64(cipher_text, ciphertext_len);

    if (output == NULL)
    {
      free(cipher_text);
      *is_null = 1;

      return NULL;
    }

    strncpy(result, output, *length);
    *length = strlen(output);

    free(output);
  }
  /* encode - hex */
  else if (strcmp(arg_format, "hex") == 0)
  {
    output = gen_hex(cipher_text, ciphertext_len);

    if (output == NULL)
    {
      free(cipher_text);
      *is_null = 1;

      return NULL;
    }

    strncpy(result, output, *length);
    *length = strlen(output);

    free(output);
  }
  /* encode - binary */
  else if (strcmp(arg_format, "binary") == 0)
  {
    output = gen_binary(cipher_text, ciphertext_len);

    if (output == NULL)
    {
      free(cipher_text);
      *is_null = 1;

      return NULL;
    }

    strncpy(result, output, *length);
    *length = strlen(output);

    free(output);
  }
  /* encode - blob */
  else
  {
    if (*length < ciphertext_len)
    {
      free(cipher_text);
      *is_null = 1;

      return NULL;
    }

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
    strcpy(message, "Called without required arguments. args:(key, encrypted_text)");
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

  int format = detect_format((const char *)cipher_text);
  unsigned char *decoded_text = NULL;
  int decoded_len = 0;

  /* decode - base64 */
  if (format == 1)
  {
    if (from_base64((const char *)cipher_text, &decoded_text, &decoded_len) != 0)
    {
      *is_null = 1;
      return NULL;
    }
  }
  /* decode - hex */
  else if (format == 2)
  {
    if (from_hex((const char *)cipher_text, &decoded_text, &decoded_len) != 0)
    {
      *is_null = 1;
      return NULL;
    }
  }
  /* decode - binary */
  else if (format == 3)
  {
    if (from_binary((const char *)cipher_text, &decoded_text, &decoded_len) != 0)
    {
      *is_null = 1;
      return NULL;
    }
  }
  /* decode - blob */
  else
  {
    decoded_text = (unsigned char *)cipher_text;
    decoded_len = args->lengths[1];
  }

  int required_len = decoded_len - NONCE_SIZE;

  if (*length < required_len)
  {
    *is_null = 1;

    // If not blob, allocated memory for decoded_text
    if (format != 0)
    {
      free(decoded_text);
    }
    return NULL;
  }

  int text_len = salsa20_decrypt(key, decoded_text, decoded_len, (unsigned char *)result);

  *length = text_len;

  // If not blob, allocated memory for decoded_text 🤯
  if (format != 0)
  {
    free(decoded_text);
  }

  return result;
}
