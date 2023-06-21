#!/bin/bash

# Define variables for domain, problem and plan files
DOMAIN="../UnsolDomain.pddl"
PROBLEM="../FinalNetworkProblem.pddl"
PLAN="../sas_plan"

# Define the command for Fast Downward validator
VALIDATE="../validate"

# Call the validator with verbose logging, passing in domain, problem and plan files
#$VALIDATE -vv $DOMAIN $PROBLEM $PLAN
#./validate -vv $DOMAIN $PROBLEM $PLAN
#./validate -vv UnsolDomain.pddl FinalNetworkProblem.pddl sas_plan

#!/bin/bash

# Run the validate command and capture its output
output=$(./validate -vv UnsolDomain.pddl FinalNetworkProblem.pddl sas_plan)

# Print the full output
echo "$output"

# Use the output in the Python script
echo "$output" | python extract_plan.py


