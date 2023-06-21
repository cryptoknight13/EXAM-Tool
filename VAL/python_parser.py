import re
import time

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
    'attacker-moves-to-admin-server-exploits-cve-2009-0241': "Attacker moves to {2} once {1} is compromised to exploit vulnerability CVE-2009-0241.",
    'attacker-connected-to-admin-server-software': "Attacker exploits vulnerable software {2}, version {3} installed on {1}.",
    'attacker-gains-access-to-file-in-software': "Attacker gains access to {3} file inside the {4} directory of {2} software of {1}.",
    'attacker-sends-request-to-file-to-initiate-dos-attack': "Attacker sends a {4} request using {3} to {2} file inside {6} to initiate {5}.",
    'attacker-compromised-admin-server': "Attacker compromises {1} through a {3}.",
        #FTP SERVER
    'attacker-moves-to-ftp-server-to-exploit-cve-2013-4465': "Once {1} compromised, attacker moves to FTP server to exploit vulnerable software {5}, {6} in {2}.",
    'attacker-connected-to-software-to-access-avatar-functionality': "Attacker connected to {3} software to get the access of avatar functionality.",
    'attackers-uploads-malicious-file-in-avatar': "Attacker does a malicious {4} in {6} in the {1}. ",
    'attacker-has-authentication-access': "Attacker get the authentication data for {3}.",
    'attacker-uploads-executable-extention-in-unspecified-directory': "Attacker uploads {1} ina na {4} on {2}.",
    'attacker-accessing-execuatble-extention-via-direct-request': "Attacker executes an {1} in a {2} via a malicious {4} process.",
    'attacker-gets-privilige-to-execute-arbitrary-code-in-ftp-server': "Attacker gains privileges to execute {2} on {3}.",
    'attacker-compromised-ftp-server': "Attacker executes {2} in {1} to compromise {1}.",
        #DNS Server
    'attacker-connected-to-dns-server-to-exploit-cve-2017-14491': "Attacker connected to {2} to exploit the vulnerability CVE-2017-14491.",
    'attacker-connected-to-vulnerable-software': "Attacker gets access to the vulnerable software {2}, version {3} installed on {1}.",
    'attacker-exploits-the-network-services': "Attacker exploits {1} software with a malicious {3}.",
    'attacker-initiates-dos-attack': "Attacker initiates {4} on {1} through the exploited {2} software.",
    'attacker-executes-arbitrary-code-via-crafted-dns-response': "Attacker executes {3} on {1} via a {5}.",
    'attacker-compromised-dns-server': "Attacker compromised {1} with the execution of mailicious {2}.",
    # Template for fail Reason...
    'configuration': "a change in the config file {1}",
    'web-software': "a change in web server software {1}",
    'web-version': "a change in web server sofware's version {1}",
    'login-page': "a change in the access of Database {1} via SQL Software",
    'sql-version': "a change in SQL Manager version {1}",
    'sql-software': "a change in Database server software {1}",
    'admin-software': "a change in admin server software {1}",
    'path': "a change in the directory location of {1}",
    'admin-file': "a change in the location or access of the file {1}",
    'admin-version': "a change in admin server sofware's version {1}",
    'ftp-version': "a change in ftp server sofware's version {1}",
    'ftp-functionality': "a change in access of {1} inside FTP server",
    'ftp-software': "a change in FTP server software {1}",
    'directory': "a change in location or access of {1} in FTP server",
    'dns-software': "a change in DNS server's software {1}",
    'dns-version': "a change in DNS server sofware's version {1}",
}
def parse_line(line):
    """Parse a line from the file into an action tuple."""
    # Remove parentheses and split by spaces
    parts = line.strip()[:].split(' ')
    # The action type is the first part, and the rest are the arguments
    return (parts[0], *parts[1:])

def parse_output(filename):
    with open(filename, 'r') as f:
        output_str = f.read()

    # Extract all steps from the output string
    all_steps = re.findall(r'(\d+):\n\((.*?)\)\n', output_str)
    #print("All Actions:", all_steps)
    # print("All the Actions in Sequence:")
    # for index, step in all_steps:
    #     print(f"{index}: {step}")

    # Find the failed step
    failed_step_match = re.search(r'Plan failed because of unsatisfied precondition in:\n\((.*?)\)', output_str)
    failed_step = failed_step_match.group(1) if failed_step_match else None
    #print("\n")
    #print("Failed Action:", failed_step)

    explanation=''

    if failed_step:
        action = parse_line(failed_step)
        action_type = action[0]
        #print(action_type)
        if action_type in templates:
            explanation += "Action ("+templates[action_type].format(*action)+") is failing because there is "
            #print(explanation)
        else:
            print(f"No template found for action type {action_type}.")
    else:
        print("No failed steps detected in the output.\n")
    
    

    # Find the reason for failure
    fail_reason_match = re.search(r'\(Set (.*?) to true\)', output_str)
    fail_reason = fail_reason_match.group(1) if fail_reason_match else None
    #print("Fail reason:", fail_reason)

    if fail_reason:
        fail_reason = fail_reason.strip('()')
        action = parse_line(fail_reason)
        action_type = action[0]
        #print(action_type)
        if action_type in templates:
            explanation += templates[action_type].format(*action)+ " and this action is no longer executable."
        else:
            print(f"No template found for action type {action_type}.")
    else:
        print("No failed steps detected in the output.\n")

    # # Print the failed step and the reason
    # if failed_step and fail_reason:
    #     # print(f"The failed Action is: {failed_step}")
    #     print(f"Explanation for Failing: {fail_reason} Precondition is not satisfing the action ({failed_step})\n")
    # else:
    #     print("No failed steps detected in the output.\n")
    print(explanation)

    # # Print all steps before the failed step
    # if failed_step:
    #     print("Actions before failure:")
    #     for step in all_steps:
    #         if step[1] == failed_step:
    #             break
    #         print(f"{step[0]}: {step[1]}")

if __name__ == "__main__":
    start_time = time.time()
    # Provide the path to the output file
    filename = "output.txt"

    parse_output(filename)
    end_time = time.time()
    execution_time = end_time - start_time

    print(f"Execution time: {execution_time} seconds")


