"""A plugin to parse a NetExec scan"""

import re
from pollenisator.core.models.ip import Ip
from pollenisator.core.models.port import Port
from pollenisator.core.components.tag import Tag
from pollenisator.server.modules.activedirectory.computer_infos import ComputerInfos
from pollenisator.server.modules.activedirectory.computers import Computer

def parse_output_file_basic_infos(nxc_file):
    """Read the given nxc file output and return a dictionary with its and a list of their open ports and infos
    Args:
        nxc_file (str): The path to the nxc text file to parse
    Returns:
        dict: A dictionary with the hosts and their open ports and infos
    """

    ### BASIC REGEX PATTERNS  ###

    # INFO: SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)

    regex_basic_info = re.compile(r"(SMB)\s+(\S+)\s+(\d+)\s+(\S+)\s+\[\*\]\s*([^\(]+)\(name:(.*)\) \(domain:(.*)\) \(signing:(True|False)\) \(SMBv1:(False|True)\)$", re.MULTILINE)

    #############################

    result_dict = {}

    # Chech if the file is empty
    nxc_file.seek(0)
    data = nxc_file.read(1)
    if not bool(data):
        result_dict['error'] = 'Empty file : The command did not return any result'
        return result_dict
    nxc_file.seek(0)

    # Parse the file once to get the basic infos
    for line in nxc_file:
        if isinstance(line, bytes):
            try:
                line = line.decode('utf-8', errors='ignore')
            except UnicodeDecodeError:
                result_dict['error'] = 'Error decoding the file'
                return result_dict
        line = line.strip()
        
        # Get infos from the basic info line
        match = regex_basic_info.match(line)
        if match:
            service, ip, port, computer_name, computer_os, computer_name_bis, domain, signing, smb1 = match.groups()
            if signing.lower() == 'true':
                signing = True
            else:
                signing = False
            if smb1.lower() == 'true':
                smb1 = True
            else:
                smb1 = False
            
            if ip not in result_dict:
                result_dict[ip] = []
            result_dict[ip].append({'port': port, 'service': service, 'domain': domain, 'computer_name': computer_name, 'computer_os': computer_os, 'signing': signing, 'smb1': smb1})
        
        if len(result_dict) == 0:
            result_dict['error'] = 'No basic info found in the file'
            return result_dict
        
    return result_dict

def update_database_basic(pentest, result_dict):
    """Add all the ips and their found open ports to the database
    Args:
        pentest: the pentest object
        result_dict: the dictionary with the hosts and their open ports and infos
    """
    targets = {}
    tags = []  # List of the tags you want to be associated with the tool NetExec

    # Check if the result dictionary is not empty
    if "error" not in result_dict:

        # Add tags for connection success
        succes_tag = Tag("info-nxc-connection-success", "green", "info", notes=f"{len(result_dict)} hosts found : \n" + "\n".join(result_dict.keys()) + "\n")

        # Iterate over the ips of the result dictionary
        for ip in result_dict.keys():

            # Get the basic infos of the current ip
            domain_name = result_dict[ip][0]['domain']
            computer_name = result_dict[ip][0]['computer_name']
            computer_os = result_dict[ip][0]['computer_os']
            signing = result_dict[ip][0]['signing']
            smb1 = result_dict[ip][0]['smb1']

            ip_infos = f"\tDomain: {domain_name}\n\tComputer name: {computer_name}\n\tOS: {computer_os}\n\tSigning: {signing}\n\tSMBv1: {smb1}\n"

            # Add the ip to the database
            ip_object = Ip(pentest).initialize(ip, notes=f"{ip_infos}\n\nPlugin: NetExec (NXCBasic)\n".replace("\t", ""), infos=result_dict[ip])
            insert_ret = ip_object.addInDb()

            # If the ip already exists, get the object
            if not insert_ret['res']:
                ip_object = Ip.fetchObject(pentest, {"_id": insert_ret['iid']})

            # Create IP success tag
            ip_tag = Tag("info-nxc-ip-found", "green", "info", notes=f"Found {ip} IP address with the following informations :\n{ip_infos}")
            ip_object.addTag(ip_tag)

            # Add the computer to the database
            computer_infos_object = ComputerInfos().initialize(computer_os, signing, smb1)
            computer_object = Computer(pentest).initialize(computer_name, ip, domain_name, infos=computer_infos_object)
            insert_ret = computer_object.addInDb()

            # If the computer already exists, get the object
            if not insert_ret['res']:
                computer_object = Computer.fetchObject(pentest, {"_id": insert_ret['iid']})

            # Create Tag if signing is disabled
            if not signing:
                signing_tag = Tag("signing-disabled", "orange", "medium", notes=f"Signing is disabled on {computer_object.name} (IP: {ip})")
                computer_object.addTag(signing_tag)

            # Create Tag if SMBv1 is enabled
            if smb1:
                smb1_tag = Tag("smbv1-enabled", "orange", "medium", notes=f"SMBv1 is enabled on {computer_object.name} (IP: {ip})")
                computer_object.addTag(smb1_tag)
            
            # Iterate over the open ports of the current ip
            for ip_port in result_dict[ip]:
                port_number = ip_port['port']
                port_service = ip_port['service']

                ip_notes = f"Port: {port_number}\nService: {port_service}\nProtocol: TCP\n\n"

                # Add the port to the database
                port_object = Port(pentest).initialize(ip, port_number, "TCP", port_service, notes=ip_notes, infos=ip_port)
                insert_ret = port_object.addInDb()

                # If the port already exists, get the object
                if not insert_ret['res']:
                    port_object = Port.fetchObject(pentest, {"_id": insert_ret['iid']})

                # Update targets dictionary
                targets[str(insert_ret['iid'])] = {"ip": ip, "port": port_number, "protocol": "tcp"}

    return targets, tags
