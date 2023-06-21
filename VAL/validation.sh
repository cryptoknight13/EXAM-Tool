#!/bin/bash

# Run your validator here and output the result
#output=$(./validate -vv LatestDomain.pddl LatestProblem.pddl sas_plan)
#output=$(./validate -vv testDomain.pddl testProblem.pddl sas_plan)
output=$(./validate -vv testDomain2.pddl testProblem2.pddl sas_plan)
# Print the output
echo "$output"
