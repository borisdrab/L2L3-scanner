CC = gcc
CFLAGS = -std=c17 -Wall -Wextra -Wpedantic -O2
LDFLAGS =
SRC = $(wildcard src/*.c)
OBJ = $(SRC:.c=.o)
TARGET = ipk-L2L3-scan
LOGIN ?= xdrabbo00

SUBMISSION_FILES := \
	src \
	tests \
	Makefile \
	README.md \
	LICENSE \
	CHANGELOG.md

.PHONY: all clean test NixDevShellName pack

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJ) $(TARGET) $(LOGIN).zip

test: $(TARGET)
	chmod +x tests/test.sh
	bash tests/test.sh

NixDevShellName:
	@echo c

pack:
	rm -f $(LOGIN).zip
	zip -r $(LOGIN).zip $(SUBMISSION_FILES) -x "src/*.o" "*.zip" ".git/*" ".DS_Store"