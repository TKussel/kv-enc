// encrypt_kv.c
// Deterministic RSAES-OAEP (SHA-256 / MGF1-SHA-256) using a custom provider
// seeded RAND seeded from sha256(public_key). Supports optional OAEP label via:
//   --label "ascii text"      OR
//   --label-hex DEADBEEF
//
// ⚠️ INSECURE (deterministic OAEP). For demo/experimentation only.

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kvnummer.h"
#include "util.h"
#include <openssl/bio.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#define SEEDED_PARAM_SEED "seed" // key of custom RAND ctx parameter

// =====================================================================================
//                         Custom Provider: "seededprng" (EVP_RAND)
// Stream: SHA256(seed || ctr_le64) using EVP (non-deprecated)
// =====================================================================================

typedef struct {
  OSSL_LIB_CTX *libctx;
  unsigned char seed[64];
  size_t seed_len;
  uint64_t ctr;
  int instantiated;
} SEEDED_RAND_CTX;

static void *seeded_rand_newctx(void *provctx, void *parent,
                                const OSSL_DISPATCH *parent_calls) {
  (void)parent;
  (void)parent_calls;
  SEEDED_RAND_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
  if (!ctx)
    return NULL;
  ctx->libctx = (OSSL_LIB_CTX *)provctx;
  return ctx;
}

static void seeded_rand_freectx(void *vctx) {
  SEEDED_RAND_CTX *ctx = (SEEDED_RAND_CTX *)vctx;
  if (!ctx)
    return;
  OPENSSL_cleanse(ctx->seed, sizeof(ctx->seed));
  OPENSSL_free(ctx);
}

static int seeded_rand_instantiate(void *vctx, unsigned int strength,
                                   int prediction_resistance,
                                   const unsigned char *pstr, size_t pstr_len,
                                   const OSSL_PARAM params[]) {
  (void)strength;
  (void)prediction_resistance;
  SEEDED_RAND_CTX *ctx = (SEEDED_RAND_CTX *)vctx;

  if (pstr && pstr_len) {
    size_t l = pstr_len > sizeof(ctx->seed) ? sizeof(ctx->seed) : pstr_len;
    memcpy(ctx->seed, pstr, l);
    ctx->seed_len = l;
    ctx->ctr = 0;
  }
  if (params) {
    const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, SEEDED_PARAM_SEED);
    if (p) {
      const void *ptr = NULL;
      size_t used = 0;
      if (!OSSL_PARAM_get_octet_string_ptr(p, &ptr, &used))
        return 0;
      size_t l = used > sizeof(ctx->seed) ? sizeof(ctx->seed) : used;
      memcpy(ctx->seed, ptr, l);
      ctx->seed_len = l;
      ctx->ctr = 0;
    }
  }
  ctx->instantiated = 1;
  return 1;
}

static int seeded_rand_uninstantiate(void *vctx) {
  SEEDED_RAND_CTX *ctx = (SEEDED_RAND_CTX *)vctx;
  ctx->instantiated = 0;
  ctx->ctr = 0;
  OPENSSL_cleanse(ctx->seed, sizeof(ctx->seed));
  ctx->seed_len = 0;
  return 1;
}

static int seeded_rand_generate(void *vctx, unsigned char *out, size_t outlen,
                                unsigned int strength,
                                int prediction_resistance,
                                const unsigned char *addin, size_t addin_len) {
  (void)strength;
  (void)prediction_resistance;
  (void)addin;
  (void)addin_len;
  SEEDED_RAND_CTX *ctx = (SEEDED_RAND_CTX *)vctx;
  if (!ctx->instantiated)
    return 0;

  unsigned char block[EVP_MAX_MD_SIZE];
  unsigned int mdlen = 0;
  size_t produced = 0;

  while (produced < outlen) {
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx)
      return 0;

    if (EVP_DigestInit_ex(mctx, EVP_sha256(), NULL) != 1) {
      EVP_MD_CTX_free(mctx);
      return 0;
    }
    if (EVP_DigestUpdate(mctx, ctx->seed, ctx->seed_len) != 1) {
      EVP_MD_CTX_free(mctx);
      return 0;
    }
    uint64_t ctr_le = ctx->ctr;
    if (EVP_DigestUpdate(mctx, &ctr_le, sizeof(ctr_le)) != 1) {
      EVP_MD_CTX_free(mctx);
      return 0;
    }
    if (EVP_DigestFinal_ex(mctx, block, &mdlen) != 1) {
      EVP_MD_CTX_free(mctx);
      return 0;
    }
    EVP_MD_CTX_free(mctx);

    ctx->ctr++;

    size_t take = (outlen - produced < mdlen) ? (outlen - produced) : mdlen;
    memcpy(out + produced, block, take);
    produced += take;
  }
  OPENSSL_cleanse(block, sizeof(block));
  return 1;
}

static int seeded_rand_reseed(void *vctx, int prediction_resistance,
                              const unsigned char *ent, size_t ent_len,
                              const unsigned char *addin, size_t addin_len) {
  (void)prediction_resistance;
  (void)addin;
  (void)addin_len;
  SEEDED_RAND_CTX *ctx = (SEEDED_RAND_CTX *)vctx;
  if (ent && ent_len > 0) {
    size_t l = ent_len > sizeof(ctx->seed) ? sizeof(ctx->seed) : ent_len;
    memcpy(ctx->seed, ent, l);
    ctx->seed_len = l;
    ctx->ctr = 0;
  }
  return 1;
}

static int seeded_rand_get_ctx_params(void *vctx, OSSL_PARAM params[]) {
  SEEDED_RAND_CTX *ctx = (SEEDED_RAND_CTX *)vctx;
  OSSL_PARAM *p;

  p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
  if (p && !OSSL_PARAM_set_int(p, ctx->instantiated ? 1 : 0))
    return 0;

  p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
  if (p && !OSSL_PARAM_set_uint(p, 256))
    return 0;

  p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
  if (p && !OSSL_PARAM_set_size_t(p, (size_t)1 << 20))
    return 0;

  return 1;
}

static const OSSL_PARAM *seeded_rand_gettable_ctx_params(void *provctx) {
  static const OSSL_PARAM gettable[] = {
      OSSL_PARAM_int(OSSL_RAND_PARAM_STATE, NULL),
      OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, NULL),
      OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL), OSSL_PARAM_END};
  (void)provctx;
  return gettable;
}

static int seeded_rand_set_ctx_params(void *vctx, const OSSL_PARAM params[]) {
  SEEDED_RAND_CTX *ctx = (SEEDED_RAND_CTX *)vctx;
  const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, SEEDED_PARAM_SEED);
  if (p) {
    const void *ptr = NULL;
    size_t used = 0;
    if (!OSSL_PARAM_get_octet_string_ptr(p, &ptr, &used))
      return 0;
    size_t l = used > sizeof(ctx->seed) ? sizeof(ctx->seed) : used;
    memcpy(ctx->seed, ptr, l);
    ctx->seed_len = l;
    ctx->ctr = 0;
  }
  return 1;
}

static const OSSL_PARAM *seeded_rand_settable_ctx_params(void *provctx) {
  static const OSSL_PARAM settable[] = {
      OSSL_PARAM_octet_string(SEEDED_PARAM_SEED, NULL, 0), OSSL_PARAM_END};
  (void)provctx;
  return settable;
}

// ---- RAND algorithm table
static const OSSL_DISPATCH seeded_rand_functions[] = {
    {OSSL_FUNC_RAND_NEWCTX, (void (*)(void))seeded_rand_newctx},
    {OSSL_FUNC_RAND_FREECTX, (void (*)(void))seeded_rand_freectx},
    {OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void))seeded_rand_instantiate},
    {OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void))seeded_rand_uninstantiate},
    {OSSL_FUNC_RAND_GENERATE, (void (*)(void))seeded_rand_generate},
    {OSSL_FUNC_RAND_RESEED, (void (*)(void))seeded_rand_reseed},
    {OSSL_FUNC_RAND_GET_CTX_PARAMS, (void (*)(void))seeded_rand_get_ctx_params},
    {OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS,
     (void (*)(void))seeded_rand_gettable_ctx_params},
    {OSSL_FUNC_RAND_SET_CTX_PARAMS, (void (*)(void))seeded_rand_set_ctx_params},
    {OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS,
     (void (*)(void))seeded_rand_settable_ctx_params},
    {0, NULL}};

static const OSSL_ALGORITHM seeded_provider_algs[] = {
    {"seededprng", NULL, seeded_rand_functions,
     "Deterministic SHA256(seed||ctr) RAND"},
    {NULL, NULL, NULL, NULL}};

typedef struct {
  OSSL_LIB_CTX *libctx;
  const OSSL_CORE_HANDLE *handle;
} SEEDED_PROV_CTX;

static const OSSL_ALGORITHM *seeded_query(void *provctx, int operation_id,
                                          int *no_cache) {
  (void)no_cache;
  (void)provctx;
  if (operation_id == OSSL_OP_RAND)
    return seeded_provider_algs;
  return NULL;
}

static void seeded_teardown(void *provctx) {
  SEEDED_PROV_CTX *pctx = (SEEDED_PROV_CTX *)provctx;
  OPENSSL_free(pctx);
}

static const OSSL_DISPATCH seeded_provider_dispatch[] = {
    {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))seeded_query},
    {OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))seeded_teardown},
    {0, NULL}};

static int seeded_provider_init(const OSSL_CORE_HANDLE *handle,
                                const OSSL_DISPATCH *in,
                                const OSSL_DISPATCH **out, void **provctx) {
  (void)in;
  SEEDED_PROV_CTX *pctx = OPENSSL_zalloc(sizeof(*pctx));
  if (!pctx)
    return 0;
  pctx->handle = handle;
  pctx->libctx = NULL;
  *out = seeded_provider_dispatch;
  *provctx = pctx;
  return 1;
}

// =====================================================================================
// MGF1 (EVP) and OAEP encode using deterministic seed from rctx
// =====================================================================================

static int mgf1(unsigned char *mask, size_t masklen, const unsigned char *seed,
                size_t seedlen, const EVP_MD *md) {
  unsigned char counter_be[4];
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int dlen = 0;
  size_t out = 0;
  uint32_t counter = 0;

  while (out < masklen) {
    counter_be[0] = (unsigned char)((counter >> 24) & 0xFF);
    counter_be[1] = (unsigned char)((counter >> 16) & 0xFF);
    counter_be[2] = (unsigned char)((counter >> 8) & 0xFF);
    counter_be[3] = (unsigned char)(counter & 0xFF);

    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx)
      return 0;
    if (EVP_DigestInit_ex(mctx, md, NULL) != 1) {
      EVP_MD_CTX_free(mctx);
      return 0;
    }
    if (EVP_DigestUpdate(mctx, seed, seedlen) != 1) {
      EVP_MD_CTX_free(mctx);
      return 0;
    }
    if (EVP_DigestUpdate(mctx, counter_be, sizeof(counter_be)) != 1) {
      EVP_MD_CTX_free(mctx);
      return 0;
    }
    if (EVP_DigestFinal_ex(mctx, digest, &dlen) != 1) {
      EVP_MD_CTX_free(mctx);
      return 0;
    }
    EVP_MD_CTX_free(mctx);

    size_t take = (masklen - out < dlen) ? (masklen - out) : dlen;
    memcpy(mask + out, digest, take);
    out += take;
    counter++;
  }
  OPENSSL_cleanse(digest, sizeof(digest));
  return 1;
}

static int oaep_encode_deterministic(EVP_RAND_CTX *rctx, unsigned char *em,
                                     size_t k, const unsigned char *msg,
                                     size_t mlen, const unsigned char *label,
                                     size_t llen, const EVP_MD *md,
                                     const EVP_MD *mgf1md) {
  // EME-OAEP (RFC 8017) with SHA-256 (default) and optional label L.
  size_t hLen = EVP_MD_get_size(md);
  if (hLen == 0)
    return 0;
  if (mlen > k - 2 * hLen - 2)
    return 0;

  // 1) lHash = Hash(label)
  unsigned char lHash[EVP_MAX_MD_SIZE];
  unsigned int lHashLen = 0;
  {
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx)
      return 0;
    if (EVP_DigestInit_ex(mctx, md, NULL) != 1) {
      EVP_MD_CTX_free(mctx);
      return 0;
    }
    if (llen && label) {
      if (EVP_DigestUpdate(mctx, label, llen) != 1) {
        EVP_MD_CTX_free(mctx);
        return 0;
      }
    }
    if (EVP_DigestFinal_ex(mctx, lHash, &lHashLen) != 1) {
      EVP_MD_CTX_free(mctx);
      return 0;
    }
    EVP_MD_CTX_free(mctx);
    if (lHashLen != hLen)
      return 0;
  }

  // 2) DB = lHash || PS || 0x01 || M  (PS = zeros)
  size_t dbLen = k - hLen - 1;
  size_t psLen = dbLen - hLen - 1 - mlen;
  unsigned char *DB = OPENSSL_zalloc(dbLen);
  if (!DB)
    return 0;
  memcpy(DB, lHash, hLen);
  // PS already zeroed
  DB[hLen + psLen] = 0x01;
  memcpy(DB + hLen + psLen + 1, msg, mlen);

  // 3) seed = random hLen bytes (here: deterministic from rctx)
  unsigned char *seed = OPENSSL_malloc(hLen);
  if (!seed) {
    OPENSSL_free(DB);
    return 0;
  }
  if (!EVP_RAND_generate(rctx, seed, hLen, 0, 0, NULL, 0)) {
    OPENSSL_free(DB);
    OPENSSL_free(seed);
    return 0;
  }

  // 4) dbMask = MGF1(seed, dbLen)
  unsigned char *dbMask = OPENSSL_malloc(dbLen);
  if (!dbMask) {
    OPENSSL_free(DB);
    OPENSSL_free(seed);
    return 0;
  }
  if (!mgf1(dbMask, dbLen, seed, hLen, mgf1md)) {
    OPENSSL_free(DB);
    OPENSSL_free(seed);
    OPENSSL_free(dbMask);
    return 0;
  }

  // 5) maskedDB = DB XOR dbMask
  for (size_t i = 0; i < dbLen; i++)
    DB[i] ^= dbMask[i];

  // 6) seedMask = MGF1(maskedDB, hLen)
  unsigned char *seedMask = OPENSSL_malloc(hLen);
  if (!seedMask) {
    OPENSSL_free(DB);
    OPENSSL_free(seed);
    OPENSSL_free(dbMask);
    return 0;
  }
  if (!mgf1(seedMask, hLen, DB, dbLen, mgf1md)) {
    OPENSSL_free(DB);
    OPENSSL_free(seed);
    OPENSSL_free(dbMask);
    OPENSSL_free(seedMask);
    return 0;
  }

  // 7) maskedSeed = seed XOR seedMask
  for (size_t i = 0; i < hLen; i++)
    seed[i] ^= seedMask[i];

  // 8) EM = 0x00 || maskedSeed || maskedDB
  em[0] = 0x00;
  memcpy(em + 1, seed, hLen);
  memcpy(em + 1 + hLen, DB, dbLen);

  OPENSSL_cleanse(lHash, sizeof(lHash));
  OPENSSL_free(DB);
  OPENSSL_free(seed);
  OPENSSL_free(dbMask);
  OPENSSL_free(seedMask);
  return 1;
}

// =====================================================================================
// Public-key loading helper (PEM)
// =====================================================================================

static EVP_PKEY *load_pubkey_pem(OSSL_LIB_CTX *libctx, const char *path) {
  (void)libctx; // using default for simplicity
  BIO *bio = BIO_new_file(path, "r");
  if (!bio)
    return NULL;
  EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
  BIO_free(bio);
  return pkey;
}

// =====================================================================================
// CLI parsing
// =====================================================================================

static void print_usage(const char *prog) {
  fprintf(
      stderr,
      "Usage:\n"
      "  %s [--label \"ascii\"] [--label-hex HEX] public.pem input.txt\n"
      "\nNotes:\n"
      "  - If both --label and --label-hex are provided, --label-hex wins.\n"
      "  - Without any label option, OAEP uses an empty label.\n",
      prog);
}

typedef struct {
  const unsigned char *label;
  size_t label_len;
  int label_alloc; // 1 if we malloc'd it and must free later
  const char *message;
  const char *pub_path;
  const char *in_path;
} cli_args;

static int parse_args(int argc, char **argv, cli_args *out) {
  memset(out, 0, sizeof(*out));
  int i = 1;

  // Parse optional flags
  while (i < argc && strncmp(argv[i], "--", 2) == 0) {
    if (strcmp(argv[i], "--label") == 0) {
      if (i + 1 >= argc)
        return 0;
      const char *s = argv[++i];
      out->label = (const unsigned char *)s;
      out->label_len = strlen(s);
      out->label_alloc = 0;
      i++;
      continue;
    } else if (strcmp(argv[i], "--label-hex") == 0) {
      if (i + 1 >= argc)
        return 0;
      unsigned char *buf = NULL;
      size_t blen = 0;
      if (!hex2bin(argv[i + 1], &buf, &blen))
        return 0;
      out->label = buf;
      out->label_len = blen;
      out->label_alloc = 1;
      i += 2;
      continue;
    } else if (strcmp(argv[i], "--help") == 0) {
      print_usage(argv[0]);
      exit(0);
    } else {
      fprintf(stderr, "Unknown option: %s\n", argv[i]);
      return 0;
    }
  }

  // Remaining positional arguments: pubkey.pem, input.txt
  if (i + 1 >= argc)
    return 0;
  out->pub_path = argv[i];
  out->in_path = argv[i + 1];
  return 1;
}

// =====================================================================================
// Hash key and ciphertext
// =====================================================================================

/**
 * Hash a public key (EVP_PKEY*) as DER-encoded SubjectPublicKeyInfo with
 * SHA-256, returning a freshly-allocated lowercase hex string
 * (null-terminated).
 *
 * Caller must OPENSSL_free() the returned string.
 * Returns NULL on error.
 */
char *pubkey_sha256_hex(const EVP_PKEY *pkey) {
  if (!pkey)
    return NULL;

  unsigned char *der = NULL; // will be allocated by i2d_PUBKEY
  int derlen = i2d_PUBKEY((EVP_PKEY *)pkey, &der);
  if (derlen <= 0) {
    return NULL;
  }

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) {
    OPENSSL_free(der);
    return NULL;
  }

  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int dlen = 0;

  int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
           EVP_DigestUpdate(ctx, der, (size_t)derlen) == 1 &&
           EVP_DigestFinal_ex(ctx, digest, &dlen) == 1;

  EVP_MD_CTX_free(ctx);
  OPENSSL_free(der);

  if (!ok || dlen == 0) {
    return NULL;
  }

  // Allocate hex string (2 chars per byte + NUL)
  char *hex = OPENSSL_malloc(dlen * 2 + 1);
  if (!hex)
    return NULL;

  static const char hexdigits[] = "0123456789abcdef";
  for (unsigned int i = 0; i < dlen; i++) {
    hex[2 * i] = hexdigits[(digest[i] >> 4) & 0xF];
    hex[2 * i + 1] = hexdigits[digest[i] & 0xF];
  }
  hex[dlen * 2] = '\0';
  return hex;
}

/**
 *  Hash a string with SHA-256 and return a Base64-encoded string.
 *
 * Caller must OPENSSL_free() the returned string.
 * Returns NULL on error.
 */
char *sha256_base64(const char *input) {
  if (!input)
    return NULL;

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx)
    return NULL;

  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int dlen = 0;

  int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
           EVP_DigestUpdate(ctx, input, strlen(input)) == 1 &&
           EVP_DigestFinal_ex(ctx, digest, &dlen) == 1;

  EVP_MD_CTX_free(ctx);

  if (!ok || dlen == 0)
    return NULL;

  // Base64 encode using BIO
  BIO *b64 = BIO_new(BIO_f_base64());
  BIO *mem = BIO_new(BIO_s_mem());
  if (!b64 || !mem) {
    BIO_free_all(b64);
    BIO_free_all(mem);
    return NULL;
  }
  // No newlines
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  BIO_push(b64, mem);

  if (BIO_write(b64, digest, dlen) <= 0 || BIO_flush(b64) != 1) {
    BIO_free_all(b64);
    return NULL;
  }

  BUF_MEM *bptr = NULL;
  BIO_get_mem_ptr(b64, &bptr);

  char *out = OPENSSL_malloc(bptr->length + 1);
  if (out) {
    memcpy(out, bptr->data, bptr->length);
    out[bptr->length] = '\0';
  }

  BIO_free_all(b64);
  return out;
}

// =====================================================================================
// main: [--label/--label-hex] public.pem input.txt-> output.txt.out
// =====================================================================================

int main(int argc, char **argv) {
  cli_args args;
  if (!parse_args(argc, argv, &args)) {
    print_usage(argv[0]);
    return 1;
  }

  // Create an isolated libctx and load providers (default/base + our built-in)
  OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
  if (!libctx) {
    fprintf(stderr, "libctx new failed\n");
    return 1;
  }

  if (!OSSL_PROVIDER_add_builtin(libctx, "seedprov", seeded_provider_init)) {
    fprintf(stderr, "add_builtin failed\n");
    return 1;
  }
  OSSL_PROVIDER *prov_def = OSSL_PROVIDER_load(libctx, "default");
  OSSL_PROVIDER *prov_base = OSSL_PROVIDER_load(libctx, "base");
  OSSL_PROVIDER *prov_seed = OSSL_PROVIDER_load(libctx, "seedprov");
  if (!prov_def || !prov_base || !prov_seed) {
    fprintf(stderr, "provider load failed\n");
    return 1;
  }
  //
  // Load public key
  EVP_PKEY *pub = load_pubkey_pem(libctx, args.pub_path);
  if (!pub) {
    fprintf(stderr, "Failed to load public key from %s\n", args.pub_path);
    return 1;
  }
  const char *seed_hex = pubkey_sha256_hex(pub);

  // Fetch deterministic RAND
  EVP_RAND *r = EVP_RAND_fetch(libctx, "seededprng", NULL);
  if (!r) {
    fprintf(stderr, "EVP_RAND_fetch seededprng failed\n");
    return 1;
  }
  char *output_name = malloc(strlen(args.in_path) + 5);
  sprintf(output_name, "%s.out", args.in_path);

#ifdef DEBUG
  printf("Debug Info CLI Arguments:\nLabel: %s\nLabelAlloc: %u\nPubkey: "
         "%s\nInput File: %s\nSeed: %s\n\n",
         args.label, args.label_alloc, args.pub_path, args.in_path, seed_hex);
#else
  printf("Encrypting File %s with\nKey %s and\nLabel %s to\nOutput File %s\n\n",
         args.in_path, args.pub_path, args.label, output_name);
#endif

  // Read input file
  size_t line_count = 0;
  char **input_lines = read_trim_input(args.in_path, &line_count);
  if (input_lines) {
    FILE *output_file = fopen(output_name, "w"); // Create/clear file
    size_t lines_processed = 0;
    size_t lines_skipped = 0;
    for (size_t i = 0; i < line_count; i++) {
      const char *current_line = input_lines[i];
      Kvnummer *current_number = deserialize_kvnummer(current_line);
      if (!current_number) {
        fprintf(stderr, "Cannot deserialize KV number: %s. Skipping...\n",
                current_line);
        lines_skipped++;
        continue;
      }
      /* if (!validate_kvnummer(current_number)) { */
      /*   fprintf(stderr, "Cannot validate KV number: %s. Skipping...\n",
       */
      /*           current_line); */
      /*   lines_skipped++; */
      /*   continue; */
      /* } */
      const char *msg = serialize_kvnummer(current_number);
      size_t mlen = strlen(msg);

      EVP_RAND_CTX *rctx = EVP_RAND_CTX_new(r, NULL);

      // Parse hex seed and instantiate PRNG
      unsigned char *seed = NULL;
      size_t seedlen = 0;
      if (!hex2bin(seed_hex, &seed, &seedlen)) {
        fprintf(stderr, "Bad hex seed\n");
        fclose(output_file);
        return 1;
      }
      OSSL_PARAM inst_params[] = {
          OSSL_PARAM_octet_string(SEEDED_PARAM_SEED, seed, seedlen),
          OSSL_PARAM_END};
      if (!EVP_RAND_instantiate(rctx, 256, 0, NULL, 0, inst_params)) {
        fprintf(stderr, "RAND instantiate failed\n");
        fclose(output_file);
        return 1;
      }
      OPENSSL_clear_free(seed, seedlen);

      // OAEP(SHA-256): hLen = 32; k = modulus size (bytes); limit mlen <= k
      // - 2*hLen - 2
      const EVP_MD *md = EVP_sha256();
      const EVP_MD *mgf1md = EVP_sha256();
      size_t hLen = EVP_MD_get_size(md);
      size_t k = (size_t)EVP_PKEY_size(pub);

      if (k < 2 * hLen + 2 || mlen > k - 2 * hLen - 2) {
        fprintf(stderr,
                "Message too long for OAEP with this key (max %zu bytes). "
                "Skipping...\n",
                k - 2 * hLen - 2);
        lines_skipped++;
        continue;
      }

      // Deterministic OAEP encode with optional label
      const unsigned char *label = args.label; // may be NULL
      size_t label_len = args.label_len;       // 0 if NULL or empty

      unsigned char *EM = OPENSSL_malloc(k);
      if (!EM) {
        fprintf(stderr, "alloc EM failed\n");
        fclose(output_file);
        return 1;
      }
      if (!oaep_encode_deterministic(rctx, EM, k, msg, mlen, label, label_len,
                                     md, mgf1md)) {
        fprintf(stderr, "OAEP encode failed\n");
        fclose(output_file);
        return 1;
      }

      // Raw RSA public encrypt (NO padding at RSA layer)
      EVP_PKEY_CTX *ectx = EVP_PKEY_CTX_new_from_pkey(libctx, pub, NULL);
      if (!ectx) {
        fprintf(stderr, "encrypt ctx failed\n");
        fclose(output_file);
        return 1;
      }
      if (EVP_PKEY_encrypt_init(ectx) <= 0) {
        fprintf(stderr, "encrypt init failed\n");
        fclose(output_file);
        return 1;
      }
      if (EVP_PKEY_CTX_set_rsa_padding(ectx, RSA_NO_PADDING) <= 0) {
        fprintf(stderr, "set no padding failed\n");
        fclose(output_file);
        return 1;
      }
      unsigned char *C = OPENSSL_malloc(k);
      size_t Clen = k;
      if (!C || EVP_PKEY_encrypt(ectx, C, &Clen, EM, k) <= 0 || Clen != k) {
        fprintf(stderr, "raw RSA encrypt failed\n");
        fclose(output_file);
        return 1;
      }
      EVP_PKEY_CTX_free(ectx);

#ifdef DEBUG
      printf("Output Ciphertext:\n");
      for (size_t i = 0; i < Clen; i++)
        printf("%02x", C[i]);
      printf("\n");
#endif

      const char *fingerprint = sha256_base64(C);
#ifdef DEBUG
      printf("KV-Nummer-Fingerprint: %s\n", fingerprint);
#endif

      fprintf(output_file, "%s\n", fingerprint);
      lines_processed++;

      // Cleanup
      OPENSSL_free(EM);
      OPENSSL_free(C);
      OPENSSL_free(fingerprint);
      EVP_RAND_uninstantiate(rctx);
      EVP_RAND_CTX_free(rctx);
      free(current_number);
      fclose(output_file);
    }
    free_input(input_lines, line_count);
    printf("Finished encrypting %zu lines, %zu lines skipped.\n",
           lines_processed, lines_skipped);
  } else {
    fprintf(stderr, "Unreadable or empty input file\n");
  }
  if (args.label_alloc && args.label)
    OPENSSL_free((void *)args.label);
  EVP_RAND_free(r);
  EVP_PKEY_free(pub);
  OPENSSL_free((void *)seed_hex);
  OSSL_PROVIDER_unload(prov_seed);
  OSSL_PROVIDER_unload(prov_base);
  OSSL_PROVIDER_unload(prov_def);
  OSSL_LIB_CTX_free(libctx);

  return 0;
}
