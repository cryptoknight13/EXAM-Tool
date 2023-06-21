import sys
import re

# Read input from stdin
input_data = sys.stdin.read()

# Find and print the "Plan Repair Advice" section
match = re.search(r'Plan Repair Advice:(.*?)Failed plans:', input_data, re.DOTALL)
if match:
    print(match.group(1).strip())
else:
    print("No Plan Repair Advice found.")
