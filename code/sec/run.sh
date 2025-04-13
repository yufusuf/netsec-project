#!/bin/bash

if [ $# -lt 2 ]; then
    echo "Usage: $0 <number_of_instances> <mean_delay_in_seconds>"
    exit 1
fi

num_instances=$1
mean_delay=$2

for ((i = 1; i <= num_instances; i++)); do
    python3 sender.py $mean_delay &
done


