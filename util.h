#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int hex2bin(const char *hex, unsigned char **out, size_t *outlen);
int save_to_file(const char *filename, const unsigned char *data,
                 size_t length);
char *trim_whitespace(char *str);
char **read_trim_input(const char *filename, size_t *line_count);
void free_input(char **lines, size_t count);

#endif // UTIL_H
