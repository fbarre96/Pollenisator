"""A plugin to parse a NetExec scan for shares"""

import re
from pollenisator.core.components.tag import Tag
from pollenisator.plugins.nxcComponents.NXCBasic import parse_output_file_basic_infos, update_database_basic
from pollenisator.server.modules.activedirectory.shares import Share

def parse_output_file_shares_infos(nxc_file):
    """Read the given nxc file output and return a dictionary with its and a list of their open ports and infos
    Args:
        nxc_file (str): The path to the nxc text file to parse
    Returns:
        dict: A dictionary with the hosts and their open ports and infos
    """

    ### SHARES REGEX PATTERNS ###

    #    ERROR: SMB         10.10.10.161    445    FOREST           [-] Error enumerating shares: STATUS_ACCESS_DENIED
    
    #    ENUM:  SMB         10.10.10.161    445    FOREST           [*] Enumerated shares
    #    1ST:   SMB         10.10.10.161    445    FOREST           Share           Permissions     Remark
    #    2ND:   SMB         10.10.10.161    445    FOREST           -----           -----------     ------
    #    3RD:   SMB         10.10.10.161    445    FOREST           ADMIN$                          Remote Admin
    #    4TH:   SMB         10.10.10.161    445    FOREST           C$                              Default share
    #    5TH:   SMB         10.10.10.161    445    FOREST           IPC$                            Remote IPC
    #    6TH:   SMB         10.10.10.161    445    FOREST           NETLOGON        READ            Logon server share
    #    7TH:   SMB         10.10.10.161    445    FOREST           SYSVOL          READ,WRITE      Logon server share

    regex_error_shares = re.compile(r"^(SMB)\s+(\S+)\s+(\d+)\s+\S+\s+\[\-\]\s*Error enumerating shares: (.+)$", re.MULTILINE)

    regex_creds = re.compile(r"^(SMB)\s+(\S+)\s+(\d+)\s+\S+\s+\[\+\]\s(\S+)\\(\S+):(\S+)$", re.MULTILINE)

    regex_enum_shares = re.compile(r"^(SMB)\s+(\S+)\s+(\d+)\s+\S+\s+\[\*\]\s*Enumerated shares$", re.MULTILINE)

    regex_columns = re.compile(r"^(SMB)\s+(\S+)\s+(\d+)\s+\S+\s+Share\s+Permissions\s+Remark$", re.MULTILINE)

    regex_separator = re.compile(r"^(SMB)\s+(\S+)\s+(\d+)\s+\S+\s+\-+\s+\-+\s+\-+$", re.MULTILINE)

    regex_lines_shares = re.compile(r"^(SMB)\s+(\S+)\s+(\d+)\s+((?:\s?\S)+)\s+((?:\s?(?:(?!WRITE|READ)\S+))+)\s+(READ|WRITE|READ,WRITE|) +(.*)$", re.MULTILINE)

    regex_basic_info = re.compile(r"(SMB)\s+(\S+)\s+(\d+)\s+(\S+)\s+\[\*\]\s*([^\(]+)\(name:(.*)\) \(domain:(.*)\) \(signing:(True|False)\) \(SMBv1:(False|True)\)$", re.MULTILINE)
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
    # Parse the file again to get the shares infos
    for line in nxc_file:
        if isinstance(line, bytes):
            try:
                line = line.decode('utf-8', errors='ignore')
            except UnicodeDecodeError:
                result_dict['error'] = 'Error decoding the file'
                return result_dict
        line = line.strip()

        # Skip the basic info, columns and separator lines
        if regex_basic_info.match(line) or regex_columns.match(line) or regex_separator.match(line):
            continue

        # Get the creds
        if regex_creds.match(line):
            username, password = regex_creds.match(line).groups()[-2:]
            creds = username + ":" + password
            continue

        # Check if shares are enumerated or not
        if regex_error_shares.match(line):
            match = regex_error_shares.match(line)
            ip = match.group(2)
            error_message = match.group(4)
            matching_index = 0
            for index, info_dict in enumerate(result_dict[ip]):
                if info_dict["port"] == match.group(3):
                    matching_index = index
                    break
            result_dict[ip]['shares'] = "Error : " + error_message
            continue
        
        # If shares are enumerated, create a new entry in the result_dict
        if regex_enum_shares.match(line):
            match = regex_enum_shares.match(line)
            ip = match.group(2)
            matching_index = 0
            for index, info_dict in enumerate(result_dict[ip]):
                if info_dict["port"] == match.group(3):
                    matching_index = index
                    break
            result_dict[ip][matching_index]['shares'] = []
            continue
        
        # Parse the shares infos
        if regex_lines_shares.match(line):
            match = regex_lines_shares.match(line)
            sharename, permission, remark = match.group(5, 6, 7)

            # Durtty fix to handle the case where the remark is empty
            if remark.strip() in ["READ", "WRITE", "READ,WRITE"]:
                permission, remark = match.group(7), ""

            matching_index = 0
            for index, info_dict in enumerate(result_dict[ip]):
                if info_dict["port"] == match.group(3):
                    matching_index = index
                    break

            result_dict[ip][matching_index]['shares'].append({'sharename': sharename, 'permission': permission, 'remark': remark, 'creds': creds})
            continue

    return result_dict

def update_database_shares(pentest, result_dict):
    """Add all the shares and their infos to the database
    Args:
        pentest: the pentest object
        ip: the ip of the host
        result_dict: the dictionary with the hosts and their open ports and infos
    """

    targets, tags = update_database_basic(pentest, result_dict)

    # Iterate over the ips of the result dictionary
    for ip in result_dict.keys():

        # Found the index of SMB port
        index_smb = 0
        for index, info_dict in enumerate(result_dict[ip]):
            if info_dict["service"] == "SMB":
                index_smb = index
                break

        # If the shares are found, add them to the database
        shares = result_dict[ip][index_smb]['shares']
        for share in shares:
            sharename = share['sharename']
            permission = share['permission']
            remark = share['remark']
            creds = share['creds']
            share_infos = {"permission": permission, "remark": remark, "creds": creds}

            # Add the share to the database
            share_object = Share(pentest).initialize(ip, sharename, infos=share_infos)
            insert_ret = share_object.addInDb()

            # If the share already exists, get the object
            if not insert_ret["res"]:
                share_object = Share.fetchObject(pentest, {"_id": insert_ret["iid"]})

            # Add the share tag
            share_tag = Tag("info-nxc-share-found", "green", "todo", notes=f"Share {sharename} found on {ip} with permission {permission} and remark {remark}")
            share_object.addTag(share_tag)

    return targets, tags
