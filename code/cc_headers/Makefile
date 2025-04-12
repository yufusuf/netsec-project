SRC = aux.c covert_channel.c
OBJ = $(SRC:.c=.o)
DEPS = aux.h covert_channel.h

CC = cc
CFLAGS =-g -I.  # Add -I. to include local headers
RM = rm -f
.PHONY: all clean

all: $(OBJ)

%.o: %.c $(DEPS)
	$(CC) -c $< -o $@ $(CFLAGS) 

clean:
	$(RM) $(OBJ)

