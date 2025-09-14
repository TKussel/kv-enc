#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char *read_file(const char *filename, size_t *length);
int save_to_file(const char *filename, const unsigned char *data,
                 size_t length);

#endif // UTIL_H
