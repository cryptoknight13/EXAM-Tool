#!/bin/bash

# Define variables for domain, problem and plan files
DOMAIN="../modified_domain_1.pddl"
PROBLEM="../domain/benchmarks/Network/FinalNetworkProblem.pddl"
PLAN="../sas_plan"

# Define the command for Fast Downward validator
VALIDATE=/Users/rakeshpodder/Documents/val/validate

# Call the validator with verbose logging, passing in domain, problem and plan files
output= ${VALIDATE} -vv $DOMAIN $PROBLEM $PLAN

