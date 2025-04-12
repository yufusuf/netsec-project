#!/bin/bash

# Check if an argument was given
if [ -z "$1" ]; then
    echo "Usage: $0 <number_of_instances>"
    exit 1
fi

# Launch the specified number of sender.py instances
for ((i = 1; i <= $1; i++)); do
    python3 sender.py &
done

# Optional: wait for all to finish
# wait

