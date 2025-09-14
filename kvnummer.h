#ifndef kvnummer_H
#define kvnummer_H

#include <sodium.h>
#include <stdbool.h>
#include <stdint.h>

enum KV_Type { kv10, kv20, kv30 };

typedef struct {
  char unchangable[9];
  char unchangable_ecc;
  char institution[9];
  char complete_ecc;
  char main_insured[9];
  char main_insured_ecc;
  enum KV_Type type;
} Kvnummer;

bool validate_kvnummer(const Kvnummer *kvnummer);
char *serialize_kvnummer(const Kvnummer *kvnummer);

Kvnummer synthetic_kvnummer10(void);
Kvnummer synthetic_kvnummer20(void);
Kvnummer synthetic_kvnummer30(void);

unsigned quersumme(unsigned n);

int validate_ecc(const char *unchangable, const char unchangable_ecc,
                 bool include_ecc);

#endif /* end of include guard: kvnummer_H */
