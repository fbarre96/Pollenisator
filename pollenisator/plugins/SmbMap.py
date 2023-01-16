"""A plugin to parse smbmap scan"""

from pollenisator.plugins.plugin import Plugin
from pollenisator.server.ServerModels.Ip import ServerIp
from pollenisator.server.ServerModels.Port import ServerPort
from pollenisator.server.modules.ActiveDirectory.computers import Computer
from pollenisator.server.modules.ActiveDirectory.shares import Share

import shlex
from pollenisator.core.Components.logger_config import logger


def smbmap_format(row):
    """Parse row of smbmap csv file
    Args:
        row: row of smbmap csv file content parsed as a list
    Returns:
        A tuple with values:
            0. if the filename matched a pattern, the pattern. None otherwise
            1. the targeted host
    """
    interesting_name_list = ["passwd", "password", "pwd", "mot_de_passe", "motdepasse", "auth",
                             "creds", "confidentiel", "confidential", "backup", ".xml", ".conf", ".cfg", "unattended"]
    interesting_type = None
    if row[3] == "f": # isDir
        for interesting_name in interesting_name_list:
            if interesting_name in row[4].lower():
                interesting_type = interesting_name
                break
    return interesting_type, row[0]

def getUserInfoFromCmdLine(cmdline=None):
    if cmdline is None:
        return None, None, None
    parts = shlex.split(cmdline)
    domain = None
    user = None
    password = None
    for part_i, part in enumerate(parts):
        if part == "-u" and user is None:
            user = parts[part_i+1]
        if part == "-d" and domain is None:
            domain = parts[part_i+1]
        if part == "-p" and password is None:
            password = parts[part_i+1]
        if part == "-no-pass":
            password = ""
    return domain, user, password

class SmbMap(Plugin):
    def getFileOutputArg(self):
        """Returns the command line paramater giving the output file
        Returns:
            string
        """
        return " --csv "

    def getFileOutputExt(self):
        """Returns the expected file extension for this command result file
        Returns:
            string
        """
        return ".csv"

    def getFileOutputPath(self, commandExecuted):
        """Returns the output file path given in the executed command using getFileOutputArg
        Args:
            commandExecuted: the command that was executed with an output file inside.
        Returns:
            string: the path to file created
        """
        return commandExecuted.split(self.getFileOutputArg())[-1].strip().split(" ")[0]


    def Parse(self, pentest, file_opened, **kwargs):
        """
        Parse a opened file to extract information
        Args:
            file_opened: the open file
            kwargs: 
                "tool" -> ToolModel if file is associated with a tool
                "cmdline" -> if cmdline was given , the command line runned to get this
        Returns:
            a tuple with 4 values (All set to None if Parsing wrong file): 
                0. notes: notes to be inserted in tool giving direct info to pentester
                1. tags: a list of tags to be added to tool 
                2. lvl: the level of the command executed to assign to given targets
                3. targets: a list of composed keys allowing retrieve/insert from/into database targerted objects.
        """
        if kwargs.get("ext", "").lower() != self.getFileOutputExt():
            return None, None, None, None
        notes = ""
        tags = []
        targets = {}
        cmdline = kwargs.get("cmdline", None)
        tool_m = kwargs.get("tool", None)
        if cmdline is None and tool_m is not None:
            cmdline = tool_m.infos.get("cmdline", None)
        domain, user, password = getUserInfoFromCmdLine(cmdline)
        interesting_files = {}
        less_interesting_notes = ""
        first_row = True
        shares = {}
        for row in file_opened:

            if isinstance(row, bytes):
                row = row.decode("utf-8")
            row = row.split(",")
            if first_row and not ','.join(row).startswith("Host,Share,Privs,isDir,Path,fileSize,Date"):
                return None, None, None, None
            elif first_row:
                first_row = False
                continue
            interesting_file_type, target = smbmap_format(row)
            share = row[1]
            privs = row[2]  
            path = row[4]
            fileSize = row[5]
            isInteresting = False
            
            if interesting_file_type is not None:
                interesting_files[interesting_file_type] = interesting_files.get(interesting_file_type, [])
                interesting_files[interesting_file_type].append(', '.join(row))
                isInteresting = True
                tags=["smbmap-interesting"]
            else:
                less_interesting_notes += ", ".join(row)+"\n"
            shares[target] = shares.get(target, {}) #{"<ip>":{"<shareName">:set(<tuple>)}}
            shares[target][share] = set(shares[target].get(share, set()))
            shares[target][share].add((path, isInteresting, privs, fileSize, domain, user))
            targets[target] = {"ip": target, "port": 445, "proto": "tcp"}
        for interesting_file_type in interesting_files.keys():
            notes += "\n=====================Interesting files:=====================\n"
            notes += str(interesting_file_type)+":\n"
            for elem in interesting_files[interesting_file_type]:
                 notes += "\t"+str(elem)+"\n"
        if less_interesting_notes.strip() != "":
            notes += "\n=====================Other files:=====================\n"+less_interesting_notes
        
        for ip, share_dict in shares.items():
            ip_m = ServerIp(pentest).initialize(ip, infos={"plugin":SmbMap.get_name()})
            insert_ret = ip_m.addInDb()
            if not insert_ret["res"]:
                ip_m = ServerIp.fetchObject(pentest, {"_id": insert_ret["iid"]})
            host = str(target)
            port = str(445)
            proto = "tcp"
            service = "netbios-ssn"
            port_m = ServerPort(pentest).initialize(host, port, proto, service, infos={"plugin":SmbMap.get_name()})
            insert_ret = port_m.addInDb()
            if not insert_ret["res"]:
                port_m = ServerPort.fetchObject(pentest, {"_id": insert_ret["iid"]})
            
            computer_m = Computer.fetchObject(pentest, {"ip":port_m.ip})
            if computer_m is not None:
                computer_m.add_user(domain, user, password)
            for share_name in share_dict:
                share_m = Share().initialize(pentest, None, host, share_name, infos={"plugin":SmbMap.get_name()})
                for share_info in share_dict[share_name]:
                    #share_info[] = path, isInteresting, privs, fileSize, domain, user
                    share_m.add_file(path=share_info[0], flagged=share_info[1], priv=share_info[2], size=share_info[3], domain=share_info[4], user=share_info[5])
                res = share_m.addInDb()
                if not res["res"]:
                    share_m.update(res["iid"])

            if password == "":
                tags += ["anon-share-found"]
        if notes.strip() != "" and not tags:
            tags = ["smbmap-todo"]
        return notes, tags, "port", targets
