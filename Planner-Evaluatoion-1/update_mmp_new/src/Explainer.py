#!/usr/bin/env python

'''
Topic   :: The driver Script for the Explanation generation
Project :: Explanations for Multi-Model Planning
Date    :: 
'''

SEARCH_OPTIONS = ["me", "mce"]

import argparse, sys
from Problem import Problem
import time

def main():
    start_time = time.time()
    
    parser = argparse.ArgumentParser(description='''The driver Script for the Explanation generation''',
                                     epilog="Usage >> ./Explainer.py -m ../domain/fetchworld-tuck-m.pddl -n" +
                                            " ../domain/fetchworld-base-m.pddl -f ../domain/problem1.pddl ")

    # Flags for the search
    parser.add_argument('--approx',   action='store_true',
                        help="Enable use of approximation (currently only supported for ME).")
    parser.add_argument('--heuristic', action='store_true',
                        help="Enable use of heuristic (currently only supported for ME)")
    parser.add_argument('--ground', action='store_true',
                        help="Consider model difference in grounded domain model")

    # Search option
    parser.add_argument('-s', '--search', type=str, help="Search to be use (ME or MCE)")

    # Arguments for the explanation
    parser.add_argument('-m', '--model',   type=str, help="Domain file with real PDDL model of robot.", required=True)
    parser.add_argument('-n', '--nmodel',  type=str, help="Domain file with human model of the robot.", required=True)
    parser.add_argument('-t', '--tmodel', type=str, help="Domain file template for the problem.", required=True)
    parser.add_argument('-p', '--problem', type=str, help="Problem file for robot.", required=True)
    parser.add_argument('-q', '--hproblem', type=str, help="Problem file for human.")
    parser.add_argument('-r', '--tproblem', type=str, help="Problem file template.", required=True)
    parser.add_argument('-f', '--plan_file',    type=str, help="Plan file.")
 

    if not sys.argv[1:] or '-h' in sys.argv[1:]:
        print (parser.print_help())
        sys.exit(1)
    args = parser.parse_args()


    if args.search.lower() not in SEARCH_OPTIONS:
        print("Unknown: Search option, please select either ME or MCE")
        sys.exit(1)


    # define problem object and run the required search
    pr_obj = Problem(args.model, args.nmodel, args.problem, args.tmodel,
     False, args.approx, args.heuristic,
     args.tproblem, args.hproblem, args.plan_file)

    if args.search.lower() == "me":
        plan = pr_obj.MeSearch()
    else:
        if args.approx and args.heuristic:
            print("MCE doesn't support heuristic or approx")
            exit(1)
        plan = pr_obj.MCESearch()
    solutions = pr_obj.solutions
    plan = pr_obj.plan
    #print(plan)
    changes = pr_obj.previous_difference

    # Convert all items to string
    str_changes = [str(item) for item in changes]
    print(str_changes)
    #for sol in solutions:
     #   print(sol)
    explanation= ''
    for item in solutions:
        explanation += "Explanation >> {}\n".format(item)

    #print(explanation.strip())
    with open('exp.dat', 'w') as explanation_file:
        explanation_file.write(explanation.strip())
   
    # Your script here
    end_time = time.time()
    execution_time = end_time - start_time

    print(f"Execution time: {execution_time} seconds")


if __name__ == '__main__':
    main()
