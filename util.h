#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int hex2bin(const char *hex, unsigned char **out, size_t *outlen);
unsigned char *read_file(const char *filename, size_t *length);
int save_to_file(const char *filename, const unsigned char *data,
                 size_t length);

#endif // UTIL_H
