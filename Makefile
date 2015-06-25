CC=gcc
CFLAGS=-W --pedantic -Wall -std=c99 -D_GNU_SOURCE -O2
LIBS=-lsodium
COMPILE=$(CC) $(CFLAGS)

SRC = $(wildcard *.c)
OBJ = $(patsubst %.c, %.o, $(SRC))
EXE = msr

$(EXE): $(OBJ)
	$(COMPILE) $(LIBS) -o $(EXE) $(OBJ)

%.o: %.c
	$(COMPILE) -c -o $@ $<

clean:
	$(RM) $(EXE) $(OBJ) nul

check-syntax:
	$(COMPILE) -o nul -S ${CHK_SOURCES}	
