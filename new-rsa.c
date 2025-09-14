// seeded_rsa_pubenc.c (OpenSSL 3.x)
// Deterministic custom RAND provider ("seededprng") + deterministic PKCS#1 v1.5 padding,
// then raw RSA public-key encryption (NO padding at RSA layer).
// ⚠️ INSECURE: deterministic v1.5 padding breaks security—demo/teaching only.

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <openssl/opensslv.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/core_dispatch.h>
#include <openssl/core.h>
#include <openssl/provider.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#define SEEDED_PARAM_SEED "seed"   // our custom RAND ctx param key

// ---------- Utility: hex -> bytes ----------
static int hex2bin(const char *hex, unsigned char **out, size_t *outlen) {
    size_t len = strlen(hex);
    if (len == 0 || (len & 1) != 0) return 0;
    size_t n = len / 2;
    unsigned char *buf = (unsigned char*)OPENSSL_malloc(n);
    if (!buf) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned int v;
        if (sscanf(hex + 2*i, "%2x", &v) != 1) { OPENSSL_free(buf); return 0; }
        buf[i] = (unsigned char)v;
    }
    *out = buf;
    *outlen = n;
    return 1;
}

// =====================================================================================
//                         Custom Provider: "seededprng" (EVP_RAND)
// Stream: SHA256(seed || ctr_le64) using EVP (non-deprecated)
// =====================================================================================

typedef struct {
    OSSL_LIB_CTX *libctx;
    unsigned char seed[64];
    size_t        seed_len;
    uint64_t      ctr;
    int           instantiated;
} SEEDED_RAND_CTX;

static void *seeded_rand_newctx(void *provctx, void *parent, const OSSL_DISPATCH *parent_calls) {
    (void)parent; (void)parent_calls;
    SEEDED_RAND_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (!ctx) return NULL;
    ctx->libctx = (OSSL_LIB_CTX *)provctx;
    return ctx;
}

static void seeded_rand_freectx(void *vctx) {
    SEEDED_RAND_CTX *ctx = (SEEDED_RAND_CTX*)vctx;
    if (!ctx) return;
    OPENSSL_cleanse(ctx->seed, sizeof(ctx->seed));
    OPENSSL_free(ctx);
}

static int seeded_rand_instantiate(void *vctx, unsigned int strength,
                                   int prediction_resistance,
                                   const unsigned char *pstr, size_t pstr_len,
                                   const OSSL_PARAM params[]) {
    (void)strength; (void)prediction_resistance;
    SEEDED_RAND_CTX *ctx = (SEEDED_RAND_CTX*)vctx;

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
            if (!OSSL_PARAM_get_octet_string_ptr(p, &ptr, &used)) return 0;
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
    SEEDED_RAND_CTX *ctx = (SEEDED_RAND_CTX*)vctx;
    ctx->instantiated = 0;
    ctx->ctr = 0;
    OPENSSL_cleanse(ctx->seed, sizeof(ctx->seed));
    ctx->seed_len = 0;
    return 1;
}

static int seeded_rand_generate(void *vctx, unsigned char *out, size_t outlen,
                                unsigned int strength, int prediction_resistance,
                                const unsigned char *addin, size_t addin_len) {
    (void)strength; (void)prediction_resistance; (void)addin; (void)addin_len;
    SEEDED_RAND_CTX *ctx = (SEEDED_RAND_CTX*)vctx;
    if (!ctx->instantiated) return 0;

    unsigned char block[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;
    size_t produced = 0;

    while (produced < outlen) {
        EVP_MD_CTX *mctx = EVP_MD_CTX_new();
        if (!mctx) return 0;

        if (EVP_DigestInit_ex(mctx, EVP_sha256(), NULL) != 1) { EVP_MD_CTX_free(mctx); return 0; }
        if (EVP_DigestUpdate(mctx, ctx->seed, ctx->seed_len) != 1) { EVP_MD_CTX_free(mctx); return 0; }
        uint64_t ctr_le = ctx->ctr;
        if (EVP_DigestUpdate(mctx, &ctr_le, sizeof(ctr_le)) != 1) { EVP_MD_CTX_free(mctx); return 0; }
        if (EVP_DigestFinal_ex(mctx, block, &mdlen) != 1) { EVP_MD_CTX_free(mctx); return 0; }
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
    (void)prediction_resistance; (void)addin; (void)addin_len;
    SEEDED_RAND_CTX *ctx = (SEEDED_RAND_CTX*)vctx;
    if (ent && ent_len > 0) {
        size_t l = ent_len > sizeof(ctx->seed) ? sizeof(ctx->seed) : ent_len;
        memcpy(ctx->seed, ent, l);
        ctx->seed_len = l;
        ctx->ctr = 0;
    }
    return 1;
}

static int seeded_rand_get_ctx_params(void *vctx, OSSL_PARAM params[]) {
    SEEDED_RAND_CTX *ctx = (SEEDED_RAND_CTX*)vctx;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
    if (p && !OSSL_PARAM_set_int(p, ctx->instantiated ? 1 : 0)) return 0;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
    if (p && !OSSL_PARAM_set_uint(p, 256)) return 0;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if (p && !OSSL_PARAM_set_size_t(p, (size_t)1<<20)) return 0;

    return 1;
}

static const OSSL_PARAM *seeded_rand_gettable_ctx_params(void *provctx) {
    static const OSSL_PARAM gettable[] = {
        OSSL_PARAM_int   (OSSL_RAND_PARAM_STATE,       NULL),
        OSSL_PARAM_uint  (OSSL_RAND_PARAM_STRENGTH,    NULL),
        OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL),
        OSSL_PARAM_END
    };
    (void)provctx;
    return gettable;
}

static int seeded_rand_set_ctx_params(void *vctx, const OSSL_PARAM params[]) {
    SEEDED_RAND_CTX *ctx = (SEEDED_RAND_CTX*)vctx;
    const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, SEEDED_PARAM_SEED);
    if (p) {
        const void *ptr = NULL;
        size_t used = 0;
        if (!OSSL_PARAM_get_octet_string_ptr(p, &ptr, &used)) return 0;
        size_t l = used > sizeof(ctx->seed) ? sizeof(ctx->seed) : used;
        memcpy(ctx->seed, ptr, l);
        ctx->seed_len = l;
        ctx->ctr = 0;
    }
    return 1;
}

static const OSSL_PARAM *seeded_rand_settable_ctx_params(void *provctx) {
    static const OSSL_PARAM settable[] = {
        OSSL_PARAM_octet_string(SEEDED_PARAM_SEED, NULL, 0),
        OSSL_PARAM_END
    };
    (void)provctx;
    return settable;
}

// ---- RAND algorithm table
static const OSSL_DISPATCH seeded_rand_functions[] = {
    { OSSL_FUNC_RAND_NEWCTX,              (void (*)(void))seeded_rand_newctx },
    { OSSL_FUNC_RAND_FREECTX,             (void (*)(void))seeded_rand_freectx },
    { OSSL_FUNC_RAND_INSTANTIATE,         (void (*)(void))seeded_rand_instantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE,       (void (*)(void))seeded_rand_uninstantiate },
    { OSSL_FUNC_RAND_GENERATE,            (void (*)(void))seeded_rand_generate },
    { OSSL_FUNC_RAND_RESEED,              (void (*)(void))seeded_rand_reseed },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS,      (void (*)(void))seeded_rand_get_ctx_params },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (void (*)(void))seeded_rand_gettable_ctx_params },
    { OSSL_FUNC_RAND_SET_CTX_PARAMS,      (void (*)(void))seeded_rand_set_ctx_params },
    { OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS, (void (*)(void))seeded_rand_settable_ctx_params },
    { 0, NULL }
};

static const OSSL_ALGORITHM seeded_provider_algs[] = {
    { "seededprng", NULL, seeded_rand_functions, "Deterministic SHA256(seed||ctr) RAND" },
    { NULL, NULL, NULL, NULL }
};

typedef struct {
    OSSL_LIB_CTX *libctx;
    const OSSL_CORE_HANDLE *handle;
} SEEDED_PROV_CTX;

static const OSSL_ALGORITHM *seeded_query(void *provctx, int operation_id, int *no_cache) {
    (void)no_cache; (void)provctx;
    if (operation_id == OSSL_OP_RAND)
        return seeded_provider_algs;
    return NULL;
}

static void seeded_teardown(void *provctx) {
    SEEDED_PROV_CTX *pctx = (SEEDED_PROV_CTX*)provctx;
    OPENSSL_free(pctx);
}

static const OSSL_DISPATCH seeded_provider_dispatch[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))seeded_query },
    { OSSL_FUNC_PROVIDER_TEARDOWN,        (void (*)(void))seeded_teardown },
    { 0, NULL }
};

static int seeded_provider_init(const OSSL_CORE_HANDLE *handle,
                                const OSSL_DISPATCH *in,
                                const OSSL_DISPATCH **out,
                                void **provctx) {
    (void)in;
    SEEDED_PROV_CTX *pctx = OPENSSL_zalloc(sizeof(*pctx));
    if (!pctx) return 0;
    pctx->handle = handle;
    pctx->libctx = NULL;
    *out = seeded_provider_dispatch;
    *provctx = pctx;
    return 1;
}

// =====================================================================================
// Deterministic PKCS#1 v1.5 padding (using our RAND)
// =====================================================================================

static int prng_bytes(EVP_RAND_CTX *rctx, unsigned char *out, size_t len) {
    return EVP_RAND_generate(rctx, out, len, 0, 0, NULL, 0);
}

static int pkcs1v15_pad_deterministic(EVP_RAND_CTX *rctx,
                                      unsigned char *em, size_t k,
                                      const unsigned char *msg, size_t mlen) {
    if (mlen > k - 11) return 0;
    em[0] = 0x00;
    em[1] = 0x02;
    size_t pslen = k - mlen - 3;
    unsigned char *PS = em + 2;

    size_t filled = 0;
    while (filled < pslen) {
        unsigned char buf[64];
        size_t need = pslen - filled;
        size_t take = need < sizeof(buf) ? need : sizeof(buf);
        if (!prng_bytes(rctx, buf, take)) return 0;
        for (size_t i = 0; i < take; i++) {
            // Force non-zero padding bytes deterministically
            PS[filled++] = (buf[i] == 0) ? 1 : buf[i];
            if (filled == pslen) break;
        }
    }
    em[2 + pslen] = 0x00;
    memcpy(em + 3 + pslen, msg, mlen);
    return 1;
}

// =====================================================================================
// Public-key loading helper (PEM)
// =====================================================================================

static EVP_PKEY *load_pubkey_pem(OSSL_LIB_CTX *libctx, const char *path) {
    (void)libctx; // using default for simplicity
    BIO *bio = BIO_new_file(path, "r");
    if (!bio) return NULL;
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return pkey;
}

// =====================================================================================
// main: seed + message + public.pem -> hex ciphertext
// =====================================================================================

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <hex-seed> \"message\" public.pem\n", argv[0]);
        return 1;
    }

    // Create an isolated libctx and load providers (default/base + our built-in)
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    if (!libctx) { fprintf(stderr, "libctx new failed\n"); return 1; }

    if (!OSSL_PROVIDER_add_builtin(libctx, "seedprov", seeded_provider_init)) {
        fprintf(stderr, "add_builtin failed\n");
        return 1;
    }
    OSSL_PROVIDER *prov_def  = OSSL_PROVIDER_load(libctx, "default");
    OSSL_PROVIDER *prov_base = OSSL_PROVIDER_load(libctx, "base");
    OSSL_PROVIDER *prov_seed = OSSL_PROVIDER_load(libctx, "seedprov");
    if (!prov_def || !prov_base || !prov_seed) {
        fprintf(stderr, "provider load failed\n");
        return 1;
    }

    // Fetch our deterministic RAND
    EVP_RAND *r = EVP_RAND_fetch(libctx, "seededprng", NULL);
    if (!r) { fprintf(stderr, "EVP_RAND_fetch seededprng failed\n"); return 1; }
    EVP_RAND_CTX *rctx = EVP_RAND_CTX_new(r, NULL);
    EVP_RAND_free(r);

    // Parse hex seed
    unsigned char *seed = NULL; size_t seedlen = 0;
    if (!hex2bin(argv[1], &seed, &seedlen)) { fprintf(stderr, "Bad hex seed\n"); return 1; }

    // Instantiate PRNG with our custom "seed" param
    OSSL_PARAM inst_params[] = {
        OSSL_PARAM_octet_string(SEEDED_PARAM_SEED, seed, seedlen),
        OSSL_PARAM_END
    };
    if (!EVP_RAND_instantiate(rctx, 256, 0, NULL, 0, inst_params)) {
        fprintf(stderr, "RAND instantiate failed\n"); return 1;
    }
    OPENSSL_clear_free(seed, seedlen);

    // Load public key
    const char *pubpath = argv[3];
    EVP_PKEY *pub = load_pubkey_pem(libctx, pubpath);
    if (!pub) { fprintf(stderr, "Failed to load public key from %s\n", pubpath); return 1; }

    // Prepare message
    const unsigned char *msg = (const unsigned char*)argv[2];
    size_t mlen = strlen(argv[2]);

    // Determine modulus size (bytes)
    size_t k = (size_t)EVP_PKEY_size(pub);
    if (k < 11 || mlen > k - 11) {
        fprintf(stderr, "Message too long for PKCS#1 v1.5 with this key (max %zu bytes)\n", k - 11);
        return 1;
    }

    // Build deterministic PKCS#1 v1.5 encoded block
    unsigned char *EM = OPENSSL_malloc(k);
    if (!EM) { fprintf(stderr, "alloc EM failed\n"); return 1; }
    if (!pkcs1v15_pad_deterministic(rctx, EM, k, msg, mlen)) {
        fprintf(stderr, "padding failed\n"); return 1;
    }

    // Raw RSA public encrypt (NO padding at RSA layer)
    EVP_PKEY_CTX *ectx = EVP_PKEY_CTX_new_from_pkey(libctx, pub, NULL);
    if (!ectx) { fprintf(stderr, "encrypt ctx failed\n"); return 1; }
    if (EVP_PKEY_encrypt_init(ectx) <= 0) { fprintf(stderr, "encrypt init failed\n"); return 1; }
    if (EVP_PKEY_CTX_set_rsa_padding(ectx, RSA_NO_PADDING) <= 0) {
        fprintf(stderr, "set no padding failed\n"); return 1;
    }
    unsigned char *C = OPENSSL_malloc(k);
    size_t Clen = k;
    if (!C || EVP_PKEY_encrypt(ectx, C, &Clen, EM, k) <= 0 || Clen != k) {
        fprintf(stderr, "raw RSA encrypt failed\n"); return 1;
    }
    EVP_PKEY_CTX_free(ectx);

    // Output ciphertext hex
    for (size_t i = 0; i < Clen; i++) printf("%02x", C[i]);
    printf("\n");

    // Cleanup
    OPENSSL_free(EM);
    OPENSSL_free(C);
    EVP_PKEY_free(pub);
    EVP_RAND_uninstantiate(rctx);
    EVP_RAND_CTX_free(rctx);
    OSSL_PROVIDER_unload(prov_seed);
    OSSL_PROVIDER_unload(prov_base);
    OSSL_PROVIDER_unload(prov_def);
    OSSL_LIB_CTX_free(libctx);
    return 0;
}

