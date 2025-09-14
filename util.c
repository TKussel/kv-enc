#include "util.h"

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
