#include "kvnummer.h"
#include "util.h" // Saving keys to and loading from files
#include <math.h> // for ceil
#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int generate_keys(void) {
  unsigned char sender_pk[crypto_box_PUBLICKEYBYTES];
  unsigned char sender_sk[crypto_box_SECRETKEYBYTES];
  char *sender_sk_b64[(unsigned)ceil(crypto_box_SECRETKEYBYTES / 3.) * 4];
  crypto_box_keypair(sender_pk, sender_sk);
  sodium_bin2base64(sender_sk_b64, sizeof sender_sk_b64, sender_sk,
                    sizeof sender_sk, sodium_base64_VARIANT_ORIGINAL);
  unsigned char recipient_pk[crypto_box_PUBLICKEYBYTES];
  unsigned char recipient_sk[crypto_box_SECRETKEYBYTES];
  char *recipient_pk_b64[(unsigned)ceil(crypto_box_PUBLICKEYBYTES / 3.) * 4];
  crypto_box_keypair(recipient_pk, recipient_sk);
  sodium_bin2base64(recipient_pk_b64, sizeof recipient_pk_b64, recipient_pk,
                    sizeof recipient_pk, sodium_base64_VARIANT_ORIGINAL);

  if (save_to_file("AOK.priv.key", sender_sk_b64, sizeof sender_sk_b64) != 0 ||
      save_to_file("OnkoFDZ.pub.key", recipient_pk_b64,
                   sizeof recipient_pk_b64) != 0) {
    printf(stderr, "Failed to generate key material. Exiting.");
    return EXIT_FAILURE;
  }
  printf("Files successfully saved as AOK.priv.key and "
         "OnkoFDZ.pub.key\n");
  return EXIT_SUCCESS;
}

int encrypt_mode(const char *onkofdz_pk_path, const char *aok_sk_path) {
  Kvnummer nummer30 = synthetic_kvnummer30();
  Kvnummer nummer20 = synthetic_kvnummer20();
  Kvnummer nummer10 = synthetic_kvnummer10();
  char *message10 = serialize_kvnummer(&nummer10);
  char *message20 = serialize_kvnummer(&nummer20);
  char *message30 = serialize_kvnummer(&nummer30);
  char *message = message30;
  unsigned msg_len = strlen(message);
  unsigned crypto_len = msg_len + crypto_box_SEALBYTES;
  unsigned char seed[randombytes_SEEDBYTES];

  size_t len1, len2;
  unsigned char onkofdz_pk[crypto_box_PUBLICKEYBYTES];
  unsigned char *onkofdz_pk_b64 = read_file(onkofdz_pk_path, &len1);
  memset(onkofdz_pk, 0, crypto_box_PUBLICKEYBYTES);
  sodium_base642bin(onkofdz_pk, sizeof onkofdz_pk, onkofdz_pk_b64,
                    sizeof onkofdz_pk_b64, NULL, NULL, NULL,
                    sodium_base64_VARIANT_ORIGINAL);
  unsigned char aok_sk[crypto_box_SECRETKEYBYTES];
  memset(aok_sk, 0, crypto_box_SECRETKEYBYTES);
  unsigned char *aok_sk_b64 = read_file(aok_sk_path, &len2);
  sodium_base642bin(aok_sk, sizeof aok_sk, aok_sk_b64, sizeof aok_sk_b64, NULL,
                    NULL, NULL, sodium_base64_VARIANT_ORIGINAL);

  if (!onkofdz_pk || !aok_sk) {
    fprintf(stderr, "Error: Could not load keys.\n");
    return EXIT_FAILURE;
  }

  // Hash PK to RNG Seed. RNG is needed for Nonce
  crypto_generichash(seed, sizeof seed, onkofdz_pk_b64, len1, NULL, 0);

  // Setup Completed, now encrypt
  unsigned char ciphertext[crypto_len];
  unsigned char nonce[crypto_box_NONCEBYTES];
  randombytes_buf_deterministic(nonce, sizeof nonce, seed);
  char *print_seed[randombytes_SEEDBYTES * 2 + 1];
  sodium_bin2hex(print_seed, sizeof(print_seed), seed, sizeof(seed));
  printf("Seed: %s\n", print_seed);

  memset(ciphertext, 0, crypto_len);
  crypto_box_easy(ciphertext, message, msg_len, nonce, onkofdz_pk, aok_sk);

  unsigned char hash[crypto_generichash_BYTES];
  crypto_generichash(hash, sizeof hash, ciphertext, crypto_len, NULL, 0);

  char *b64hash[(unsigned)ceil(crypto_generichash_BYTES / 3.) * 4];
  sodium_bin2base64(b64hash, sizeof b64hash, hash, crypto_generichash_BYTES,
                    sodium_base64_VARIANT_URLSAFE);
  printf("Encoded KV: %s\n", b64hash);
  /* printf("Truncated: %s, %llu\n", print_truncated, truncated); */
  return EXIT_SUCCESS;
}

int test_mode(void) {
  Kvnummer nummer30 = synthetic_kvnummer30();
  Kvnummer nummer20 = synthetic_kvnummer20();
  Kvnummer nummer10 = synthetic_kvnummer10();
  char *message10 = serialize_kvnummer(&nummer10);
  char *message20 = serialize_kvnummer(&nummer20);
  char *message30 = serialize_kvnummer(&nummer30);
  printf("Serialized KV10: %s\n", message10);
  printf("Serialized KV20: %s\n", message20);
  printf("Serialized KV30: %s\n", message30);

  char test[9] = {'T', '0', '0', '8', '3', '3', '1', '5', '1'};
  char *test2 = "10312113";

  printf("Result validation: %u\n", validate_ecc(test, '8', true));
  printf("Result validation2: %u\n", validate_ecc(test2, '7', false));

  return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [generate|encrypt] [options]\n", argv[0]);
    return EXIT_FAILURE;
  }
  if (sodium_init() < 0) {
    fprintf(stderr, "Failed to initialize libsodium.\n");
    return EXIT_FAILURE;
  }
  if (strcmp(argv[1], "generate") == 0) {
    return generate_keys();
  } else if (strcmp(argv[1], "test") == 0) {
    return test_mode();
  } else if (strcmp(argv[1], "encrypt") == 0) {
    if (argc == 4) {
      const char *onkofdz_pk_path = argv[2];
      const char *aok_sk_path = argv[3];

      if (!onkofdz_pk_path || !aok_sk_path) {
        fprintf(stderr,
                "Usage: %s encrypt <onkofdz public key file> <aok secret "
                "key file>\n",
                argv[0]);
        return EXIT_FAILURE;
      }
      return encrypt_mode(onkofdz_pk_path, aok_sk_path);
    } else {
      fprintf(stderr,
              "Usage: %s encrypt <onkofdz public key file> <aok secret "
              "key file>\n",
              argv[0]);
      return EXIT_FAILURE;
    }
  } else {
    fprintf(stderr, "Invalid mode: %s. Use 'generate' or 'encrypt'.\n",
            argv[1]);
    return EXIT_FAILURE;
  }
}
