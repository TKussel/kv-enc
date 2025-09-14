#include "kvnummer.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *serialize_kvnummer(const Kvnummer *kvnummer) {
  char *result;
  switch (kvnummer->type) {
  case kv10: {
    result = (unsigned char *)malloc(20);
    break;
  }
  case kv20: {
    result = (unsigned char *)malloc(40);
    break;
  }
  case kv30: {
    result = (unsigned char *)malloc(60);
    break;
  }
  }
  unsigned counter = 0;
  for (unsigned i = 0; i < 9; counter += 2, i++) {
    sprintf(&result[counter], "%.2X", kvnummer->unchangable[i]);
  }
  sprintf(&result[counter], "%.2X", kvnummer->unchangable_ecc);
  counter += 2;
  if (kvnummer->type == kv20 || kvnummer->type == kv30) {
    for (unsigned i = 0; i < 9; counter += 2, i++) {
      /* sprintf(&result[2 * i + 10], "%.2x", kvnummer->institution[i]); */
      sprintf(&result[counter], "%.2x", kvnummer->institution[i]);
    }
  }
  if (kvnummer->type == kv30) {
    for (unsigned i = 0; i < 9; counter += 2, i++) {
      /* sprintf(&result[2 * i + 38], "%.2x", kvnummer->main_insured[i]); */
      sprintf(&result[counter], "%.2x", kvnummer->main_insured[i]);
    }
    /* sprintf(&result[56], "%.2x", kvnummer->main_insured_ecc); */
    sprintf(&result[counter], "%.2x", kvnummer->main_insured_ecc);
    counter += 2;
  }
  /* sprintf(&result[58], "%.2x", kvnummer->complete_ecc); */
  if (kvnummer->type == kv20 || kvnummer->type == kv30)
    sprintf(&result[counter], "%.2x", kvnummer->complete_ecc);
  return result;
}

Kvnummer synthetic_kvnummer30(void) {
  Kvnummer result = {
      .unchangable = {'T', '1', '2', '3', '4', '5', '6', '7', '8'},
      .unchangable_ecc = '5',
      .institution = {'1', '2', '3', '4', '5', '6', '7', '8', '9'},
      .complete_ecc = '4',
      .main_insured = {'F', '2', '3', '4', '5', '6', '7', '8', '9'},
      .main_insured_ecc = '1',
      .type = kv30};
  return result;
}
Kvnummer synthetic_kvnummer20(void) {
  Kvnummer result = {
      .unchangable = {'T', '1', '2', '3', '4', '5', '6', '7', '8'},
      .unchangable_ecc = '5',
      .institution = {'1', '2', '3', '4', '5', '6', '7', '8', '9'},
      .complete_ecc = '4',
      .type = kv20};
  return result;
}
Kvnummer synthetic_kvnummer10(void) {
  Kvnummer result = {
      .unchangable = {'T', '1', '2', '3', '4', '5', '6', '7', '8'},
      .unchangable_ecc = '5',
      .type = kv10};
  return result;
}

unsigned quersumme(unsigned n) {
  unsigned result = 0;
  while (n > 0) {
    result += n % 10;
    n /= 10;
  }
  return result;
}

int validate_ecc(const char *number, const char ecc, bool include_ecc) {
  printf("Strlen: %lu\n", strlen(number));
  unsigned count = 0;
  if (include_ecc)
    count = quersumme(2 * (ecc - '0'));
  for (int i = strlen(number) - 1; i >= 0; i--) {
    int value = 0;
    if ((int)number[i] > 90) // lowercase
      value = number[i] - 'a' + 1;
    else if ((int)number[i] > 57) // Uppercase
      value = number[i] - 'A' + 1;
    else
      value = number[i] - '0';
    unsigned inter = quersumme((i % 2 == 0 ? 1 : 2) * value);
    printf("Value: %u, weight: %i, result: %u\n", value, (i % 2 == 0 ? 1 : 2),
           inter);
    count += quersumme((i % 2 == 0 ? 1 : 2) * value);
  }
  printf("Sum: %u, modulo: %u\n", count, count % 10);
  return (count % 10) == (ecc - '0');
}
bool validate_kvnummer(const Kvnummer *kvnummer) {
  // parse uchangable + institution
  switch (kvnummer->type) {
  case kv10: {
    return validate_ecc(kvnummer->unchangable, kvnummer->unchangable_ecc, true);
  }
  case kv20: {
    char full_number[19];
    strcpy(full_number, kvnummer->unchangable);
    full_number[9] = kvnummer->unchangable_ecc;
    strcat(full_number, kvnummer->institution);
    return validate_ecc(full_number, kvnummer->complete_ecc, false);
  }
  case kv30: {
    char full_number[29];
    strcpy(full_number, kvnummer->unchangable);
    full_number[9] = kvnummer->unchangable_ecc;
    strcat(full_number, kvnummer->institution);
    strcat(full_number, kvnummer->main_insured);
    full_number[28] = kvnummer->main_insured_ecc;
    return validate_ecc(full_number, kvnummer->complete_ecc, false);
  }
  }
  return false;
}
