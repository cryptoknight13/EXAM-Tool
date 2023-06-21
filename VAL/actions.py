# Define templates for each action type
templates = {
    'access-to-webserver': "Attacker has access to webserver {1}.",
    'attacker-connected-to-web-server-exploits-cve-2015-1635': "The attacker connect to {1} through {3} to exploit vulnerability CVE-2015-1635.",
    'attacker-exploits-vulnerable-software-version': "Attacker exploits vulnerable software {2}, version {3} installed on {1}.",
    'attacker-changes-server-configuration': "Attacker executes malicious {2} on {4} config file of software {3} to chnage {1} configuration.",
    'attacker-gains-privileges-by-executing-malicious-file': "Attacker gains privileges to execute {3} on {1}.",
    'attacker-execute-code-to-compromise-web-server': "Attacker executes {1} in {2} to compromise {2}.",
    'attacker-moves-to-database-server-exploits-cve-2014-1466': "Attacker moves to {2} once {1} is compromised to exploit vulnerability CVE-2014-1466.",
    'attacker-connected-to-vulnerable-software-version': "Attacker exploits vulnerable software {2}, version {3} installed on {1}.",
    'attacker-uploads-malicious-sql-code-to-software': "Attacker do a {3} on software {2} that is installed in {1}.",
    'attacker-opens-login-page-in-application-through-software': "Attacker gets access to login page of Database Server through software {1}.",
    'attacker-gains-access-to-login-field': "Attacker gain access to login-page of the login-field in {2}.",
    'attacker-executes-malicious-sql-code-in-login-field': "Attacker executes malicious {1} in the login field of login page.",
    'attacker-compromises-database-server': "Attacker executes {2} in {1} to compromise {1}.",
    # Add more templates as needed...
}
def parse_line(line):
    """Parse a line from the file into an action tuple."""
    # Remove parentheses and split by spaces
    parts = line.strip()[1:-1].split(' ')
    # The action type is the first part, and the rest are the arguments
    return (parts[0], *parts[1:])

def generate_text(input_filename, output_filename):
    """Read actions from a file and generate human-readable text."""
    with open(input_filename, 'r') as infile, open(output_filename, 'w') as outfile:
        count = 1
        for line in infile:
            action = parse_line(line)
            action_type = action[0]
            if action_type in templates:
                outfile.write(str(count)+". "+templates[action_type].format(*action) + '\n')
                count=count+1
            else:
                print(f"No template for action type '{action_type}'")

# Usage
generate_text('sas_plan', 'output.txt')
