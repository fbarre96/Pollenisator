"""A plugin to parse a CrackMapExex scan"""

import re
from pollenisator.server.ServerModels.Ip import ServerIp
from pollenisator.server.ServerModels.Port import ServerPort
from pollenisator.core.plugins.plugin import Plugin
import json

def getInfos(enum4linux_file):
    parts = ["Starting enum4linux", "Target Information", "Enumerating Workgroup/Domain", "Session Check on", 
       "Users on", "Groups on", "enum4linux complete on"]
    infos = {"domain_users":{}}
    current_part = -1
    found_marker = False
    regex_user = re.compile(r"^index: 0x[\da-f]+ RID: 0x[\da-f]+ \S+: 0x[\da-f]+ Account: (.+)(?=\s+Name:)\s+Name:.+(?=Desc:)Desc: (.+)$")
    regex_group = re.compile(r"^Group '([^']+)' \(RID: \d+\) has member: ([^\\]+)\\(.+)$")
    for line in enum4linux_file:
        if isinstance(line, bytes):
            line = line.decode("utf-8")
        for i,part in enumerate(parts):
            if part in line:
                current_part = i
        if current_part == 0: #"Starting enum4linux",
            found_marker = True
        elif current_part == 1: #"Target Information"
            if line.startswith("Target "):
                infos["ip"] = line.strip().split(" ")[-1]
            if line.startswith("Username "):
                infos["username"] = "'".join(line.strip().split("'")[1:-1])
            if line.startswith("Password "):
                infos["password"] = "'".join(line.strip().split("'")[1:-1])
        elif current_part == 2: #"Enumerating Workgroup/Domain"
            if line.startswith("[+] Got domain/workgroup name: "):
                infos["domain"] = line.strip().split(" ")[-1].lower()
        elif current_part == 3: #"Session Check on"
            if line.startswith("[+] Server"):
                if "doesn't allow session" in line:
                    infos["session_allowed"] = False
                    return infos
                else:
                    infos["session_allowed"] = True
        elif current_part == 4: # user on
            found = re.search(regex_user, line)
            if found is not None:
                account = found.group(1)
                desc = found.group(2)
                infos["domain_users"][infos["domain"]+"\\"+account] = {"desc":desc}
        elif current_part == 5: # Groups on
            found = re.search(regex_group, line)
            if found is not None:
                group = found.group(1)
                domain = found.group(2).lower()
                member = found.group(3)
                user_info = infos["domain_users"].get(domain+"\\"+member, {})
                user_info["groups"] = set(user_info.get("groups", []))
                user_info["groups"].add(str(group))
                user_info["groups"] = list(user_info["groups"])
                infos["domain_users"][domain+"\\"+member] = user_info
        elif current_part == 6: #enum4linux complete
            return infos
    if found_marker:
        return infos
    return None

def updateDatabase(pentest, enum_infos):
    """
    Add all the ips and theirs ports found after parsing the file to the scope object in database.
    Args:
        hostsInfos: the dictionnary with ips as keys and a list of dictionnary containing ports informations as value.
    """
    # Check if any ip has been found.
    if enum_infos is None:
        return
    ip_m = ServerIp().initialize(str(enum_infos["ip"]))
    insert_ret = ip_m.addInDb()
    port_m = ServerPort().initialize(str(enum_infos["ip"]), "445", "tcp", "netbios-ssn")
    insert_ret = port_m.addInDb()
    port_m = ServerPort.fetchObject(pentest, {"_id": insert_ret["iid"]})
    targets = {"enum4linux":{"ip": enum_infos["ip"], "port": "445", "proto": "tcp"}}
    infosToAdd = enum_infos
    if enum_infos.get("session_allowed", False):
        creds = (enum_infos.get("domain", ""), enum_infos.get("username", ""), enum_infos.get("password", ""))
        port_m.infos["users"] = list(set(map(tuple, port_m.infos.get("users", []))).union(creds))
    if "users" in infosToAdd:
        del infosToAdd["users"]
    if "admins" in infosToAdd:
        del infosToAdd["admins"]
    port_m.updateInfos(infosToAdd)
    return targets

class Enum4Linux(Plugin):
    """Inherits Plugin
    A plugin to parse a enum4linux scan"""

    def getFileOutputArg(self):
        """Returns the command line paramater giving the output file
        Returns:
            string
        """
        return " | tee "

    def getFileOutputExt(self):
        """Returns the expected file extension for this command result file
        Returns:
            string
        """
        return ".log.txt"

    def getFileOutputPath(self, commandExecuted):
        """Returns the output file path given in the executed command using getFileOutputArg
        Args:
            commandExecuted: the command that was executed with an output file inside.
        Returns:
            string: the path to file created
        """
        return commandExecuted.split(self.getFileOutputArg())[-1].strip().split(" ")[0]


    def Parse(self, pentest, file_opened, **_kwargs):
        """
        Parse a opened file to extract information
       
        Args:
            file_opened: the open file
            _kwargs: not used
        Returns:
            a tuple with 4 values (All set to None if Parsing wrong file): 
                0. notes: notes to be inserted in tool giving direct info to pentester
                1. tags: a list of tags to be added to tool 
                2. lvl: the level of the command executed to assign to given targets
                3. targets: a list of composed keys allowing retrieve/insert from/into database targerted objects.
        """
        notes = ""
        tags = []
        enum_infos = getInfos(file_opened)
        notes = json.dumps(enum_infos, indent=4)
        if enum_infos is not None and enum_infos.get("users") is not None:
            tags = ["enum4linux-success"]
        elif enum_infos is None:
            return None, None, None, None
        targets = updateDatabase(pentest, enum_infos)
        return notes, tags, "ports", targets
