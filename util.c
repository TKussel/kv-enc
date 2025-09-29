#include "util.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int hex2bin(const char *hex, unsigned char **out, size_t *outlen) {
  size_t len = strlen(hex);
  if (len == 0 || (len & 1) != 0)
    return 0;
  size_t n = len / 2;
  unsigned char *buf = (unsigned char *)malloc(n);
  if (!buf)
    return 0;
  for (size_t i = 0; i < n; i++) {
    unsigned int v;
    if (sscanf(hex + 2 * i, "%2x", &v) != 1) {
      free(buf);
      return 0;
    }
    buf[i] = (unsigned char)v;
  }
  *out = buf;
  *outlen = n;
  return 1;
}

int save_to_file(const char *filename, const unsigned char *data,
                 size_t length) {
  FILE *f = fopen(filename, "wb");
  if (!f) {
    perror("Failed to write output file");
    return -1;
  }
  fwrite(data, sizeof(data[0]), length, f);
  fclose(f);
  return 0;
}

// Trim whitespace in place
char *trim_whitespace(char *str) {
  char *end;

  while (isspace((unsigned char)*str))
    str++;

  if (*str == 0) // All spaces?
    return str;

  end = str + strlen(str) - 1;
  while (end > str && isspace((unsigned char)*end))
    end--;

  *(end + 1) = '\0';

  return str;
}

// read file lines into an array trimmed
char **read_trim_input(const char *filename, size_t *line_count) {
  FILE *fp = fopen(filename, "r");
  if (!fp) {
    perror("Failed to open file");
    return NULL;
  }

  size_t capacity = 16; // initial capacity
  size_t count = 0;
  char **lines = malloc(capacity * sizeof(char *));
  if (!lines) {
    perror("Memory allocation failed");
    fclose(fp);
    return NULL;
  }

  char buffer[1024]; // line buffer
  while (fgets(buffer, sizeof(buffer), fp)) {
    char *trimmed = trim_whitespace(buffer);
    if (*trimmed == '\0')
      continue; // skip empty lines

    // Duplicate trimmed line
    char *line_copy = strdup(trimmed);
    if (!line_copy) {
      perror("Memory allocation failed");
      break;
    }

    // Expand array if needed
    if (count >= capacity) {
      capacity *= 2;
      char **new_lines = realloc(lines, capacity * sizeof(char *));
      if (!new_lines) {
        perror("Memory reallocation failed");
        free(line_copy);
        break;
      }
      lines = new_lines;
    }

    lines[count++] = line_copy;
  }

  fclose(fp);

  *line_count = count;
  return lines;
}

// Free the allocated input lines array
void free_input(char **lines, size_t count) {
  for (size_t i = 0; i < count; i++) {
    free(lines[i]);
  }
  free(lines);
}
