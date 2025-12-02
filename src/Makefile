CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -Werror -pedantic -O2
BUILD_DIR = ../build
TARGET = $(BUILD_DIR)/cipher
SRC = cipher.c logger.c

all: cipher

cipher: $(TARGET)

$(TARGET): $(SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

# optional second target (kept for compatibility)
logging_cipher: $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -f $(TARGET)

.PHONY: all cipher logging_cipher clean
