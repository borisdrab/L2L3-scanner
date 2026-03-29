CC = gcc
CFLAGS = -std=c17 -Wall -Wextra -Wpedantic -O2
LDFLAGS =
SRC = $(wildcard src/*.c)
OBJ = $(SRC:.c=.o)
TARGET = ipk-L2L3-scan

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJ) $(TARGET)

test: $(TARGET)
	@echo "No tests  provided yet."

NixDevShellName:
	@echo c
