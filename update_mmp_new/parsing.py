import re
import ast
import os
import pddl
from pddl import parse_domain, parse_problem
from pddl import formatter
from collections import defaultdict



def read_state_from_domain_file(domainFileName, problemFileName):
    domain = parse_domain(domainFileName)
    problem = parse_problem(problemFileName)
    state = []

    #Process domain name
    domain_name = domain.name
    state.append(f"domain-has-name-{''.join([str(l) for l in domain_name])}")

    #Process types
    types = domain.types
    state.append(f"types-has-{' '.join([str(t) for t in types])}")

    # Process Requirements
    requirements = ' '.join([str(req) for req in domain.requirements])
    state.append(f"requirements-has-{requirements}")

    # Process predicates
    for predicate in domain.predicates:
        predicate_name = predicate.name
        predicate_params = {}
        #predicate_params = " ".join([str(param) for param in predicate.terms])
        for param in predicate.terms:
            predicate_params[param.name] = str(param.type_tags).strip("{}") if param.type_tags else "set()"
           #print(param.name + " - " + str(param.type_tags).strip("{}"))
        state.append(f"predicate-{predicate_name}-has-parameters-{predicate_params}")

    
    # need to be debugged
    for action in domain.actions:
        actionName = action.name
        paramlist = []
        for p in action.parameters:
            paramname =  str(p).replace("?","")
            paramtype = str(p.type_tags) if p.type_tags else "set()"
            paramlist.append(f"{paramname} - {paramtype}")
        formatparams = " ".join(paramlist)
        item = f"action-{actionName}-has-parameters-and-types-{formatparams}"
        state.append(item)
        preds = str(action.precondition).strip("()").split(" ") 
        preds[-1] += ")"
        precondpred = " ".join(preds)
        state.append(f"action-{actionName}-has-preconditions-{precondpred}")
        effs = str(action.effect).strip("()").split(" ")
        effs[-1] += ")"
        effectpred = " ".join(effs)
        state.append(f"action-{actionName}-has-effects-{effectpred}")

    # Process Problem Name
    problem_name = problem.name
    state.append(f"problem-has-name-{problem_name}")

    # Process objects
    for o in problem.objects:
        state.append(f"object-{o.name}-has-type-{o.type_tags}")

    # Process initial state to debug
    init = problem.init
    for pred in init:
        initpredname = pred.name
        for char in pred.terms:
            initpredconst = char
            state.append(f"init-{initpredname}-has-constants-{initpredconst}")
    
    # Process goal state to debug
    goal = str(problem.goal).strip("()").split(" ")
    goal[-1] += ")"
    goalpred = " ".join(goal)
    state.append(f"goal-has-{goalpred}")

    return state


def write_domain_file_from_state(state, domain_output_file, problem_output_file):
    init_state = []
    goal_state = []
    types =[]
    actnames = []
    actparams = []
    actprec = []
    acteff = []
    domain_name = ""
    problem_name = ""
    objects = []
    predicates = []
    requirements = []
    objects = []
    action_dict = {}
    for item in state:
        key,value = item.split("has-",1)
        if "domain-" in key:
            domain_name = value.strip("name").strip("-")
        elif "problem-" in key:
            problem_name = value[5:]
        elif "requirements-" in key:
            value = value.strip("-")
            for i,item in enumerate(value):
                if item.startswith(":"):
                    requirements.append(item)
                else:
                    requirements[-1] += f"{item}"
            requirements = "".join(requirements)
        elif "types-" in key:
            for values in value:
                types.append(values)
            types = "".join(types)
        elif "predicate-" in key:
            predname = key.strip("predicate")
            predname = predname.strip("- -")
            predparams = value.strip("parameters-")
            if "set()" in predparams:
                predparams = predparams.replace("set()"," ")
                predparams.strip("{}")
            predparams = predparams.replace(":","")
            predparams = predparams.replace("'","")
            predparams = predparams.replace('"','').replace("{","").replace("}","").split(",")
            for param in predparams:
                words = param.split()
                if len(words)>1:
                    indi = predparams.index(param)
                    hyphenpos = param.find(" ")
                    param = param[:hyphenpos] + "-" + param[hyphenpos + 1:]
                    predparams[indi] = param
                #twohyph = [s for s in param if s.find("- -") == True]
            for param in predparams:
                if param.startswith("-"):
                    indi = predparams.index(param)
                    param = param.lstrip("-")
                    hyphenpos = param.find(" ")
                    param = param[:hyphenpos] + "-" + param[hyphenpos + 1:]
                    del predparams[indi]
                    predparams.append(param)
            outputparams = " ".join(["?" + param.strip() for param in predparams if param])
            rawpreds = predname+ " " + outputparams
            predicate = rawpreds.strip('')  
            predicates.append(predicate)
        elif "action-" in key:
            actname = key.strip("action")
            actname = actname.strip("- -")
            actnames.append(actname)
            actnames = list(set(actnames))
            actinfo = value.strip("-")
            if "parameters-and-types-" in actinfo:
                actparams = actinfo.split("types-")
                actparams = actparams[1]
                if "set()" in actparams:
                    actparams = actparams.replace("- set()"," ")
                    actparams = actparams.replace("'",'').replace("{","").replace("}","").split()
                    for act in actparams:
                        if act == "-":
                            acti = actparams.index(act)
                            actparams[acti] = act + " " + actparams[acti+1]
                            del actparams[acti+1]
                        if "-" not in act:
                            acti = actparams.index(act)
                            act = "?" + act
                            actparams[acti] = act
                    actparams = " ".join(actparams)
                else:
                    actparams = actinfo.replace("'",'').replace("{","").replace("}","").split()
                    for act in actparams:
                        if act == "-":
                            acti = actparams.index(act)
                            actparams[acti] = act + " " + actparams[acti+1]
                            del actparams[acti+1]
                        if "-" not in act:
                            acti = actparams.index(act)
                            act = "?" + act
                            actparams[acti] = act
                    actparams = " ".join(actparams)
            if "preconditions-" in actinfo:
                actprecs = actinfo.split("preconditions-")[1] 
                if "not" in actprecs:
                    actprecs = actprecs + ")"
                actprec.append(actprecs)
            if "effects-" in actinfo:
                acteffs = actinfo.split("effects-")[1]
                if "not" in acteffs:
                    acteffs = acteffs + ")"
                acteff.append(acteffs)
        elif "object-" in key:
            octname = key.strip("object")
            octname = octname.strip("- -")
            octtype = value.strip("type")
            octtype = octtype.strip("-")
            if octtype == "set()":
                octtype = ""
            octtype = octtype.replace("'","").replace("{","").replace("}","")
            probobj = octname + "-" + octtype
            if probobj[-1] == "-":
                probobj = probobj.rstrip("-")
            objects.append(probobj)
        elif "init-" in key:
            initpredname = key.strip("init")
            initpredname = initpredname.strip("- -")
            initval = value.strip("constants")
            initval = initval.strip("- -")
            initpred = "(" + initpredname + " " + initval + ")"
            init_state.append(initpred)
        elif "goal-" in key:
            goal_state = "(" + value + ")"
    for name,pre,eff in zip(sorted(actnames),sorted(actprec),sorted(acteff)):
        action_dict[name] = [actparams,pre,eff]
    #print(action_dict)
    domain_str = f"(define (domain {domain_name})\n"
    domain_str += f"(:requirements {requirements})\n"
    domain_str += f"(:types {types})\n"

    domain_str += f"(:predicates\n"
    for predicate in predicates:
        domain_str += f"({predicate})\n"
    domain_str += ")"

    for action_name, action_info in action_dict.items():
        domain_str += f"\n(:action {action_name}\n"
        domain_str += f"  :parameters ({action_info[0]})\n"
        domain_str += f"  :precondition ({action_info[1]})\n"
        domain_str += f"  :effect  ({action_info[2]})\n"
        domain_str += f")"
    domain_str += f"\n)"
    problem_str = f"(define (problem {problem_name})\n"
    problem_str += f"(:domain {domain_name})\n"
    problem_str += f"(:objects \n"  
    for object in objects:
       problem_str += f"{object}\n"
    problem_str += f")\n"
    problem_str += f"(:init\n"
    for pred in init_state:
        problem_str += f"{pred}\n"
    problem_str += f")\n"

    problem_str += f"(:goal {goal_state})\n"
    problem_str += ")\n"
    problem_str += ")"

    with open(domain_output_file, "w") as domain_file:
        domain_file.write(domain_str)

    with open(problem_output_file, "w") as problem_file:
        problem_file.write(problem_str)

state = read_state_from_domain_file("NetworkDomain.pddl", "NetworkProblem.pddl")
print(state)
write_domain_file_from_state(state, "output_domain.pddl", "output_problem.pddl")

