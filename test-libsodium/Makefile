#
CC=gcc
LIBSODIUM=$(HOME)/builds/libsodium

CFLAGS=-c -Werror -Wall -Wextra -pedantic -Wno-long-long \
 -I$(LIBSODIUM)/include

# -ggdb -O0 -finstrument-functions

LDFLAGS=-L$(LIBSODIUM)/lib -lsodium

SOURCES=sodium_version.c

OBJECTS=$(SOURCES:.c=.o)

EXECUTABLE=sodium_version

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@

check:
	./$(EXECUTABLE)

clean:
	rm -rf *o $(EXECUTABLE)
