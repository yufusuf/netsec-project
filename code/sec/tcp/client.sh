#!/bin/bash

echo "Hello client " | nc insec 8888 -v -q 1
