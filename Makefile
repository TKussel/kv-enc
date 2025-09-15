CC = gcc
CSTD = gnu17
# CFLAGS = -Wall -Wextra -pedantic -std=$(CSTD) -O2 -I /opt/homebrew/include/
CFLAGS = -Wall -Wextra -pedantic -std=$(CSTD) -O0 -ggdb -I /opt/homebrew/include/
LDFLAGS = -lcrypto -ldl -L /opt/homebrew/lib/

SRC = main.c \
			kvnummer.c \
      util.c

HDR =  kvnummer.h \
			util.h

OBJ = $(SRC:.c=.o)

TARGET = kv-encrypt

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET) $(LDFLAGS)

%.o: %.c $(HDR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)
