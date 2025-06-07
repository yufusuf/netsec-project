# code/Makefile

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Icc_headers

# Paths
CC_HEADERS = cc_headers
C_PROCESSOR_DIR = c-processor
CC_RECEIVER_DIR = insec/cc_receiver

# Executables
PROCESSOR_EXEC = $(C_PROCESSOR_DIR)/processor
RECEIVER_EXEC = $(CC_RECEIVER_DIR)/receiver

.PHONY: all c-processor receiver run_processor run_receiver clean

# Default target
all: c-processor receiver

# Build c-processor
c-processor:
	$(MAKE) -C $(C_PROCESSOR_DIR) 

# Build cc_receiver
receiver:
	$(MAKE) -C $(CC_RECEIVER_DIR)

# Run c-processor
run_processor: c-processor
	./$(PROCESSOR_EXEC)

# Run cc_receiver
run_receiver: receiver
	./$(RECEIVER_EXEC)

# Clean everything
clean:
	$(MAKE) -C $(C_PROCESSOR_DIR) clean
	$(MAKE) -C $(CC_RECEIVER_DIR) clean

