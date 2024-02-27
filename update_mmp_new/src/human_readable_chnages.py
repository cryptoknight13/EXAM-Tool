def human_readable(change):
    # This function assumes that 'change' is a set of strings, 
    # where each string is a change description.
    
    formatted_changes = []
    
    for item in change:
        split_item = item.split(" ", 1)
        
        if len(split_item) == 2:
            key, value = split_item
            if key == 'has-initial-state-configuration':
                formatted_changes.append(f"Change the {value} configuration file location or directory inside the Web Server")
            elif key == 'has-initial-state-web-software':
                formatted_changes.append(f"Restrict the access to software {value} or update the {value} to another software")
            elif key == 'has-initial-state-web-version':
                formatted_changes.append(f"Upgrade the web server software's version {value} to a more recent version")
            elif key == 'has-initial-state-login-page':
                formatted_changes.append(f"Restrict the access to {value} via SQL Manager")
            elif key == 'has-initial-state-sql-software':
                formatted_changes.append(f"Restrict the access to SQL software {value} or update the {value} to another software")
            elif key == 'has-initial-state-sql-version':
                formatted_changes.append(f"Upgrade the SQL server software's version {value} to a more recent version")
            elif key == 'has-initial-state-admin-version':
                formatted_changes.append(f"Upgrade the admin server software's version {value} to a more recent version")
            elif key == 'has-initial-state-admin-file':
                formatted_changes.append(f"Restrict the access to file {value} via Admin Software")
            elif key == 'has-initial-state-admin-software':
                formatted_changes.append(f"Restrict the access to Admin software {value} or update the {value} to another software")
            elif key == 'has-initial-state-path':
                formatted_changes.append(f"Change the path of {value} directory inside the Admin software")
            elif key == 'has-initial-state-ftp-software':
                formatted_changes.append(f"Restrict the access to FTP software {value} or update the {value} to another software")
            elif key == 'has-initial-state-directory':
                formatted_changes.append(f"Remove any {value} or restrict the access of directory inside the FTP server.")
            elif key == 'has-initial-state-ftp-version':
                formatted_changes.append(f"Upgrade the FTP server software's version {value} to a more recent version")
            elif key == 'has-initial-state-ftp-functionality':
                formatted_changes.append(f"Restrict the access of {value} of the software installed on FTP server")
            elif key == 'has-initial-state-dns-software':
                formatted_changes.append(f"Restrict the access to DNS server software {value} or update the {value} to another software")
            elif key == 'has-initial-state-dns-version':
                formatted_changes.append(f"Upgrade the DNS server software's version {value} to a more recent version")
        # else:
        #     formatted_changes.append(f"Unknown change: {item}")

    return ', or '.join(formatted_changes)

def parse_change_string(change_string):
    # remove unnecessary characters including newline characters
    clean_string = change_string.replace("changes >> ", "").replace("set()","").replace("{", "").replace("}", "").replace("'", "").strip()
    # split into individual change strings
    #change_strings = [item for item in clean_string if item != ['']]
    change_strings = clean_string.split(", ")
    return change_strings


# Read the changes from 'change.dat' file
with open('changes.dat', 'r') as input_file:
       # changes = [parse_change_string(line) for line in input_file]
       changes = [parse_change_string(line) for line in input_file if line.strip("''")]
       changes = [item for item in changes if item != ['']]

# Write the human-readable changes to 'formatted_changes.txt' file
with open('formatted_changes.txt', 'w') as output_file:
    for change in changes:
            formatted_change = human_readable(change)
            output_file.write("Suggested Changes >> "+formatted_change)
            output_file.write("\n")

