# code/insec/cc_receiver/Makefile

CC = gcc
CFLAGS = -Wall -I../../cc_headers

SRC = main.c ../../cc_headers/aux.c ../../cc_headers/covert_channel.c
OBJ = $(SRC:.c=.o)
LIBS = -lpcap -lm -lcrypto -lnats -lpthread
TARGET = receiver

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

run: all
	./$(TARGET)

clean:
	rm -f $(OBJ) $(TARGET)

