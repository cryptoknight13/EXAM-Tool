#!/bin/bash

# Run The Validation Script

./validation.sh > output.txt
python3 python_parser.py
