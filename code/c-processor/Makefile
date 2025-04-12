PROCESSOR = processor
SRC = main.c aux.o covert_channel.o
OBJ = $(SRC:.c=.o)

CC = cc
RM = rm -f

CFLAGS = -g -I/usr/include
LIBS = -lpcap -lm -lcrypto -lnats
LDFLAGS = 

.PHONY: all clean debug

all: ../cc_headers/aux.o ../cc_headers/covert_channel.o $(PROCESSOR)

# Build main receiver
$(PROCESSOR): main.o aux.o covert_channel.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

# Compile main.o
main.o: main.c
	$(CC) -c $< -o $@ $(CFLAGS)

# Call external make and copy .o files locally
../cc_headers/aux.o ../cc_headers/covert_channel.o:
	$(MAKE) -C ../cc_headers
	@cp ../cc_headers/aux.o ../cc_headers/covert_channel.o .

debug: CFLAGS += -ggdb
debug: all

clean:
	$(MAKE) -C ../cc_headers clean
	$(RM) *.o $(PROCESSOR)

