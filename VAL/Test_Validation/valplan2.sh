#!/bin/bash

output=$(./validate -vv UnsolDomain.pddl FinalNetworkProblem.pddl sas_plan) # replace this with your actual command

repair_advice=$(echo "$output" | awk '/Plan Repair Advice:/{flag=1;next}/Failed plans:/{flag=0}flag')

echo "$repair_advice"
