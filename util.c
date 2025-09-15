#include "util.h"

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

unsigned char *read_file(const char *filename, size_t *length) {
  FILE *f = fopen(filename, "rb");
  if (!f) {
    perror("Failed to open file");
    return NULL;
  }

  fseek(f, 0, SEEK_END);
  *length = ftell(f);
  rewind(f);

  unsigned char *buffer = malloc(*length);
  if (!buffer) {
    perror("Memory allocation failed");
    fclose(f);
    return NULL;
  }

  fread(buffer, sizeof(buffer[0]), *length, f);
  fclose(f);
  return buffer;
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
