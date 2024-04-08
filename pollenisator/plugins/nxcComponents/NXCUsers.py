"""A plugin to parse a NetExec scan"""

import re
from pollenisator.core.components.tag import Tag
from pollenisator.plugins.nxcComponents.NXCBasic import parse_output_file_basic_infos, update_database_basic
from pollenisator.server.modules.activedirectory.computers import Computer
from pollenisator.server.modules.activedirectory.users import User

def parse_output_file_user_infos(nxc_file):
    """Read the given nxc file output and return a dictionary with its and a list of their open ports and infos
    Args:
        nxc_file (str): The path to the nxc text file to parse
    Returns:
        dict: A dictionary with the hosts and their open ports and infos
    """

    ### USERS REGEX PATTERNS  ###

    # INFO: SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)

    regex_basic_info = re.compile(r"(SMB)\s+(\S+)\s+(\d+)\s+(\S+)\s+\[\*\]\s*([^\(]+)\(name:(.*)\) \(domain:(.*)\) \(signing:(True|False)\) \(SMBv1:(False|True)\)$", re.MULTILINE)

    regex_smb_enum_users = re.compile(r"^(SMB)\s+(\S+)\s+(\d+)\s+\S+\s+\[\+\]\s*Enumerated domain user\(s\)$", re.MULTILINE)

    regex_smb_user = re.compile(r"^(SMB)\s+(\S+)\s+(\d+)\s+\S+\s+[^\[]+\\((?:\s?\S)+)(?:.*)$", re.MULTILINE)

    regex_ldap_enum_users = re.compile(r"^(LDAP)\s+(\S+)\s+(\d+)\s+\S+\s+\[\*\]\s*Total of records returned \d+$", re.MULTILINE)

    regex_ldap_user = re.compile(r"^(LDAP)\s+(\S+)\s+(\d+)\s+\S+\s+(.+)", re.MULTILINE)

    #############################

    result_dict = {}

    # Chech if the file is empty
    nxc_file.seek(0)
    data = nxc_file.read(1)
    if not bool(data):
        result_dict['error'] = 'Empty file : The command did not return any result'
        return result_dict

    # Parse the file once to get the basic infos
    result_dict = parse_output_file_basic_infos(nxc_file)

    nxc_file.seek(0) # Reset the file pointer to the beginning of the file
    # Parse the file again to get the users infos
    for line in nxc_file:
        if isinstance(line, bytes):
            try:
                line = line.decode('utf-8', errors='ignore')
            except UnicodeDecodeError:
                result_dict['error'] = 'Error decoding the file'
                return result_dict
        line = line.strip()

        # Skip the basic info, columns and separator lines
        if regex_basic_info.match(line):
            continue

        # Check if SMB or LDAP users enumeration is performed
        if regex_smb_enum_users.match(line) or regex_ldap_enum_users.match(line):
            if regex_smb_enum_users.match(line):
                match = regex_smb_enum_users.match(line)
            else:
                match = regex_ldap_enum_users.match(line)
            service, ip, port = match.group(1, 2, 3)
            matching_index = 0
            for index, info_dict in enumerate(result_dict[ip]):
                if info_dict["port"] == port:
                    matching_index = index
                    break
                if index == len(result_dict[ip]) - 1:
                    result_dict[ip].append({'port': port, 'service': service})
                    matching_index = index + 1
            result_dict[ip][matching_index]["users"] = []
            continue

        # Get the users from smb
        match = regex_smb_user.match(line)
        if match:
            ip, port, user = match.group(2, 3, 4)
            matching_index = 0
            for index, info_dict in enumerate(result_dict[ip]):
                if info_dict["port"] == port:
                    matching_index = index
                    break
            result_dict[ip][matching_index]["users"].append({'username': user.lower()})
            continue

        # Get the users from ldap
        match = regex_ldap_user.match(line)
        if match and '[+]' not in line:
            service, ip, port, user = match.group(1, 2, 3, 4)
            matching_index = 0
            for index, info_dict in enumerate(result_dict[ip]):
                if info_dict["port"] == port:
                    matching_index = index
                    break
            user = user.strip().split(',')
            result_dict[ip][matching_index]["users"].append(user)
            continue

    return result_dict

def update_database_users(pentest, result_dict):
    """Add all the users and their infos to the database
    Args:
        pentest: the pentest object
        result_dict: the dictionary with the hosts and their open ports and infos
    """

    targets, tags = update_database_basic(pentest, result_dict)

    # Iterate over the ips of the result dictionary
    for ip in result_dict.keys():

        user_index = 0
        for index, info_dict in enumerate(result_dict[ip]):
            if 'users' in info_dict:
                user_index = index
                break

        # If the users are found, add them to the database
        users = result_dict[ip][user_index]["users"]

        # Retrieve the computer object corresponding to the ip
        computer_object = Computer.fetchObject(pentest, {"ip": ip})

        for user in users:
            # If SMB user
            if result_dict[ip][user_index]["service"] == "SMB":
                username = user["username"]
                user_id = computer_object.add_user(ip, username, "", infos=user)
                user_tag = Tag("info-nxc-user-found", "green", "todo", notes="User "+username+" found on "+ip+" with SMB service")
                user_object = User.fetchObject(pentest, {"_id": user_id})
                user_object.addTag(user_tag)

            # If LDAP user !! Uniformiser la sortie LDAP à l'object User (userame, password, etc.)
            if result_dict[ip][user_index]["service"] == "LDAP":
                # Only take the first CN value for the username
                for user_info in user:
                    if "CN=" in user_info:
                        username = user_info[3:]
                        break
                user_id = computer_object.add_user(ip, username, "", infos=user)
                user_tag = Tag("info-nxc-user-found", "green", "todo", notes="User "+username+" found on "+ip+" with LDAP service")
                user_object = User.fetchObject(pentest, {"_id": user_id})
                user_object.addTag(user_tag)

    return targets, tags
