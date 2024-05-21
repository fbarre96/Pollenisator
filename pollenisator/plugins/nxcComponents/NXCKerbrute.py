"""A plugin to parse a NetExec scan"""

import re
from pollenisator.plugins.nxcComponents.NXCBasic import parse_output_file_basic_infos, update_database_basic
from pollenisator.core.components.tag import Tag
from pollenisator.server.modules.activedirectory.computers import Computer

def parse_output_file_kerbrute(nxc_file):
    """Read the given nxc file output and return a dictionary with its and a list of their open ports and infos
    Args:
        nxc_file (str): The path to the nxc text file to parse
    Returns:
        dict: A dictionary with the hosts and their open ports and infos
    """

    ### KERBRUTE REGEX PATTERNS  ###

    regex_basic_info = re.compile(r"(SMB)\s+(\S+)\s+(\d+)\s+(\S+)\s+\[\*\]\s*([^\(]+)\(name:(.*)\) \(domain:(.*)\) \(signing:(True|False)\) \(SMBv1:(False|True)\)$", re.MULTILINE)

    regex_found = re.compile(r"^(SMB|LDAP)\s+(\S+)\s+(\d+)\s+(\S+)\s+\[\-\]\s\S*\\(\S*):(\S*)\s(KDC_ERR_PREAUTH_FAILED)$", re.MULTILINE)

    regex_asreproast = re.compile(r"^(SMB|LDAP)\s+(\S+)\s+(\d+)\s+(\S+)\s+\[\+\]\s\S*\\(\S*)\s(account vulnerable to asreproast attack)$", re.MULTILINE)

    regex_hash = re.compile(r"^(SMB|LDAP)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\$krb5asrep\$\d*\$?(\S+)\@\S*)$", re.MULTILINE)

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
    # Parse the file again to get the exisiting users and potentially asreproast vulnerable users
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

        # Check if the user is found
        match = regex_found.match(line)
        if match:
            ip, port, username = match.group(2, 3, 5)
            for index, info_dict in enumerate(result_dict[ip]):
                if info_dict["port"] == port:
                    # Check if the userlist is already present
                    if 'users' not in result_dict[ip][index]:
                        result_dict[ip][index]['users'] = []
                    # If the user list is already present, check if the user is already in the list
                    for user in result_dict[ip][index]['users']:
                        if user['username'].lower() == username.lower():
                            user['asreproast'] = False
                            break
                    else:
                        result_dict[ip][index]['users'].append({'username': username.lower(), 'asreproast': False})
            continue

        # Check if the user is asreproast vulnerable
        match = regex_asreproast.match(line)
        if match:
            ip, port, username = match.group(2, 3, 5)
            for index, info_dict in enumerate(result_dict[ip]):
                if info_dict["port"] == port:
                    # Check if the userlist is already present
                    if 'users' not in result_dict[ip][index]:
                        result_dict[ip][index]['users'] = []
                    # If the user list is already present, check if the user is already in the list
                    for user in result_dict[ip][index]['users']:
                        if user['username'].lower() == username.lower():
                            user['asreproast'] = True
                            break
                    else:
                        result_dict[ip][index]['users'].append({'username': username.lower(), 'asreproast': True})
            continue

        # Check if the hash is found
        match = regex_hash.match(line)
        if match:
            ip, port, asrep_hash, username = match.group(2, 3, 5, 6)
            for index, info_dict in enumerate(result_dict[ip]):
                if info_dict["port"] == port:
                    # Check if the userlist is already present
                    if 'users' not in result_dict[ip][index]:
                        result_dict[ip][index]['users'] = []
                    # If the user list is already present, check if the user is already in the list
                    for user in result_dict[ip][index]['users']:
                        if user['username'].lower() == username.lower():
                            user["asreproast"] = True
                            user['asrep_hash'] = asrep_hash
                            break
                    else:
                        result_dict[ip][index]['users'].append({'username': username.lower(), 'asreproast': True, 'asrep_hash': asrep_hash})
            continue

    return result_dict

def update_database_kerbrute(pentest, result_dict):
    """Add all the users and their infos to the database
    Args:
        pentest: the pentest object
        result_dict: the dictionary with the hosts and their open ports and infos
    """

    targets, tags = update_database_basic(pentest, result_dict)

    # Iterate over the ips of the result dictionary
    for ip in result_dict.keys():

        # Retrieve the computer object corresponding to the ip
        computer_object = Computer.fetchObject(pentest, {"ip": ip})

        # If the users are found, add them to the database
        for info_dict in result_dict[ip]:
            if 'users' in info_dict:
                for user in info_dict['users']:
                    username = user['username']

                    computer_object.add_user(ip, username, '', infos=user)
                    computer_object.fetchObject(pentest, {"ip": ip})

                    if user['asreproast']:
                        asrep_tag = Tag("asreproastable-user", "orange", "high", notes="User "+username+" is asreproastable on "+ip+" with port "+info_dict['port']+"\n")
                        tags.append(asrep_tag)

                    if 'asrep_hash' in user:
                        asrep_hash = user['asrep_hash']
                        old_secrets = computer_object.infos.secrets
                        if asrep_hash not in old_secrets:
                            old_secrets.append(asrep_hash)
                            # Update the secrets
                            computer_object.updateInfos({"secrets": old_secrets})

                        asrep_hash_tag = Tag("asrep-hash-found", "red", "high", notes="ASREP hash found for user "+username+" on "+ip+" with port "+info_dict['port']+" :\n\n"+asrep_hash+"\n")
                        tags.append(asrep_hash_tag)


    return targets, tags
