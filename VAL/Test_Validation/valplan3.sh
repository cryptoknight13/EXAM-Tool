#!/bin/bash

output=$(./validate -vv UnsolDomain.pddl FinalNetworkProblem.pddl sas_plan) # replace this with your actual command

valid_steps=$(echo "$output" | awk '/Plan size:/{flag=1;next}/Plan Validation details/{flag=0}flag')

failed_step=$(echo "$output" | awk '/Plan failed because/{flag=1;next}/Plan failed to execute/{flag=0}flag')

echo "Valid Steps:"
echo "$valid_steps"

echo -e "\nFailing Step and Reason:"
echo "$failed_step"
