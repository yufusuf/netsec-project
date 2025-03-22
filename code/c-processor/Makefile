
PROCESSOR = processor
SRC = main.c
OBJ = $(SRC:.c=.o)

CC = cc
RM = rm

CFLAGS = -g -I/usr/include
LIBS = -lpcap -lnats -lm
LDFLAGS = 


.PHONY: clean

all: $(PROCESSOR)

debug: CFLAGS += -ggdb -O0
debug: $(PROCESSOR)

$(PROCESSOR): $(OBJ)
	$(CC) -o $@ $(OBJ) $(CFLAGS) $(LIBS)

.c.o: 
	$(CC) -c $< $(CFLAGS)

clean:
	$(RM) ./$(OBJ) ./$(PROCESSOR)
