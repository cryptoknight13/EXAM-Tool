import re
import subprocess

def parse_failed_step(output):
    fail_pattern = re.compile(r"Plan failed because of unsatisfied precondition in:\n(.*)\n\n\nPlan failed to execute\n\nPlan Repair Advice:\n\n(.*)\n\nFailed plans:")
    match = re.search(fail_pattern, output)

    if match:
        failed_action = match.group(1)
        unsatisfied_precondition = match.group(2)

        explanation = f"The action '{failed_action}' failed because its precondition '{unsatisfied_precondition}' was not satisfied."
        return explanation

    else:
        return "No failed steps detected in the output."


def run_shell_script(script_path):
    # Run the shell script and capture the output
    result = subprocess.run(['bash', script_path], stdout=subprocess.PIPE)
    return result.stdout.decode()


output = run_shell_script("./valplan3.sh")
print(parse_failed_step(output))
