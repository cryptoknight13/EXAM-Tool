#!/bin/bash

# Run your validator here and output the result
output=$(./validate -vv UnsolDomain.pddl FinalNetworkProblem.pddl sas_plan)

# Print the output
echo "$output"


def parse_failed_output(filename):
    with open(filename, 'r') as f:
        content = f.read()
        
    failed_step_pattern = r'\((.*?)\) has an unsatisfied precondition at time (\d+)'
    unsatisfied_precondition_pattern = r'Set \((.*?)\) to true'

    failed_step_match = re.search(failed_step_pattern, content)
    unsatisfied_precondition_match = re.search(unsatisfied_precondition_pattern, content)

    if failed_step_match and unsatisfied_precondition_match:
        failed_step = failed_step_match.group(1)
        unsatisfied_precondition = unsatisfied_precondition_match.group(1)
        print(f'The step "{failed_step}" failed because the precondition "{unsatisfied_precondition}" was not satisfied.')
    else:
        print('No failed steps detected in the output.')
