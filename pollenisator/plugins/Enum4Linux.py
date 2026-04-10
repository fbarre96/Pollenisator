"""A plugin to parse a CrackMapExex scan"""

import re

from pollenisator.core.components.tag import Tag
from pollenisator.core.models.ip import Ip
from pollenisator.core.models.port import Port
from pollenisator.server.modules.activedirectory.computers import Computer
from pollenisator.server.modules.activedirectory.users import User
from pollenisator.plugins.plugin import Plugin
from pollenisator.plugins.plugin_result import PluginResult, InfoUpdate, UserLink
from pollenisator.core.components.utils import performLookUp
import json
import shlex

def remove_term_colors(data):
    return re.sub(r'\x1b\[[0-9;]+[a-zA-Z]', '', data)

def getInfos(enum4linux_file):
    parts = [["Starting enum4linux", "ENUM4LINUX"], "Target Information", "via LDAP", "via SMB", "Workgroup/Domain", "Session Check on",
             "Users", "Groups", ["complete", "Completed"]]
    infos = {"domain_users": {}, "computers": {}}
    current_part = -1
    found_marker = False
    regex_user = re.compile(r"^index: 0x[\da-f]+ RID: 0x[\da-f]+ \S+: 0x[\da-f]+ Account: (.+)(?=\s+Name:)\s+Name:.+(?=Desc:)Desc: (.+)$")
    regex_group = re.compile(r"^Group '([^']+)' \(RID: \d+\) has member: ([^\\]+)\\(.+)$")
    ng_regex_user = re.compile(r"'\d+':\n\s+username: (.+)\n\s+name: (.+)\n\s+acb: '(.+)'\n\s+description: (.+)", re.MULTILINE)
    ng_regex_groups = re.compile(r"'\d+':\n\s+groupname: (.+)\n\s+type: (.+)", re.MULTILINE)
    global_users = ""
    global_groups = ""
    for line in enum4linux_file:
        if isinstance(line, bytes):
            try:
                line = line.decode("utf-8", errors="ignore")
            except UnicodeDecodeError:
                return None
        for i,part in enumerate(parts):
            if isinstance(part, list):
                for p in part:
                    if p in line:
                        current_part = i
            elif part in line:
                current_part = i
        line = remove_term_colors(line)

        if current_part == 0: #"Starting enum4linux",
            found_marker = True
        elif current_part == 1: #"Target Information"
            if "Target " in line:
                infos["ip"] = line.strip().split(" ")[-1]
            if "Username" in line and "Random Username" not in line:
                infos["username"] = "'".join(line.strip().split("'")[1:-1])
            elif "Random Username" in line:
                infos["random_username"] = "'".join(line.strip().split("'")[1:-1])
            if line.startswith("Password "):
                infos["password"] = "'".join(line.strip().split("'")[1:-1])
        elif current_part == 2: #"Enumerating LDAP info"
            if "Long domain name is" in line:
                infos["domain"] = line.strip().split(" ")[-1].lower()
        elif current_part == 3: #"via SMB"
            if "DNS domain:" in line:
                infos["domain"] = line.strip().split("DNS domain: ")[-1].strip().lower()
        elif current_part == 4: #"Enumerating Workgroup/Domain"
            if "[+] Got domain/workgroup name: " in line:
                netbios_domain = line.strip().split(" ")[-1].lower()
                if "domain" in infos:
                    if netbios_domain not in infos["domain"]:
                        infos["domain"] = netbios_domain+"."+infos["domain"]
                else:
                    infos["domain"] = netbios_domain
        elif current_part == 5: #"Session Check on"
            if line.startswith("[+] Server"):
                if "doesn't allow session" in line:
                    infos["session_allowed"] = False
                    return infos
                else:
                    infos["session_allowed"] = True
                    username = line.split("username '")[1].split("'")[0]
                    if username.strip() == "" or username.strip() == infos.get("random_username"):
                        infos["null_session_allowed"] = True

        elif current_part == 6: # user on
            found = re.search(regex_user, line)
            if found is not None:
                account = found.group(1)
                desc = found.group(2)
                infos["domain_users"][infos["domain"]+"\\"+account] = {"desc":desc}
            else:
                global_users += line
        elif current_part == 7: # Groups on
            # also means that users are finished
            if global_users != "":
                users = re.findall(ng_regex_user, global_users)
                for user in users:
                    if len(user) == 4:
                        # username, name, acb, description
                        account = user[0]
                        desc = user[3]
                        infos["domain_users"][infos["domain"]+"\\"+account] = {"desc":desc}
            found = re.search(regex_group, line)
            if found is not None:
                group = found.group(1)
                domain = found.group(2).lower()
                member = found.group(3)
                user_info = infos["domain_users"].get(domain+"\\"+member, {})
                user_info["groups"] = set(user_info.get("groups", []))
                user_info["groups"].add(str(group))
                user_info["groups"] = list(user_info["groups"])
                if member.endswith("$"):
                    ip = performLookUp(member[:-1]+"."+domain, nameservers=[infos["ip"]])
                    if ip is not None:
                        infos["computers"][member] = {"ip":ip, "member":member, "domain":domain}
                else:    
                    infos["domain_users"][domain+"\\"+member] = user_info
            else:
                global_groups += line
        elif current_part == 8: #enum4linux complete
            # also means that groups are finished
            if global_groups != "":
                groups = re.findall(ng_regex_groups, global_groups)
                for group in groups:
                    if len(group) == 2:
                        # groupname, type
                        groupname = group[0]
                        type_group = group[1]
                        pass # nothing implemented for groups without user info

            return infos
    if found_marker:
        return infos
    return None

def collectEnumResults(pentest, enum_infos, result):
    """
    Collect all the ips, ports, computers and users found after parsing the file into the PluginResult.
    Args:
        pentest: pentest identifier
        enum_infos: the dictionary with parsed enum4linux info.
        result: PluginResult to collect into
    Returns:
        targets dict
    """
    # Check if any ip has been found.
    if enum_infos is None:
        return
    result.ips.append(Ip(pentest).initialize(str(enum_infos["ip"]), infos={"plugin": Enum4Linux.get_name()}))
    result.ports.append(Port(pentest).initialize(str(enum_infos["ip"]), "445", "tcp", "netbios-ssn", infos={"plugin": Enum4Linux.get_name()}))
    targets = {"enum4linux": {"ip": enum_infos["ip"], "port": "445", "proto": "tcp"}}
    infosToAdd = dict(enum_infos)
    if enum_infos.get("session_allowed", False):
        creds = (enum_infos.get("domain", ""), enum_infos.get("username", "anonymous"), enum_infos.get("password", ""))
        result.user_links.append(UserLink(
            computer_ip=str(enum_infos["ip"]),
            domain=creds[0],
            username=creds[1],
            password=creds[2],
            is_admin=False
        ))
    for user_account, user_add_infos in enum_infos.get("domain_users", {}).items():
        domain = user_account.split("\\")[0]
        username = user_account.split("\\")[1]
        password = ""
        user_m = User(pentest).initialize(domain, username, password, user_add_infos.get("groups", []), user_add_infos.get("desc"))
        result.users.append(user_m)
    for computer, computer_infos in enum_infos.get("computers", {}).items():
        result.ips.append(Ip(pentest).initialize(str(computer_infos["ip"]), infos={"plugin": Enum4Linux.get_name()}))
        comp_m = Computer(pentest).initialize(computer, computer_infos["ip"], computer_infos["domain"], infos={"plugin": Enum4Linux.get_name()})
        result.computers.append(comp_m)
    if "users" in infosToAdd:
        del infosToAdd["users"]
    if "admins" in infosToAdd:
        del infosToAdd["admins"]
    result.info_updates.append(InfoUpdate(
        collection="ports",
        db_key={"ip": str(enum_infos["ip"]), "port": "445", "proto": "tcp"},
        infos=infosToAdd
    ))
    return targets


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
        if part == "-w" and domain is None:
            domain = parts[part_i+1]
        if part == "-p" and password is None:
            password = parts[part_i+1]
        if part == "-no-pass":
            password = ""
    return domain, user, password

class Enum4Linux(Plugin):
    """Inherits Plugin
    A plugin to parse a enum4linux scan"""
    default_bin_names = ["enum4linux","enum4linux.pl","enum4linux-ng"]
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

    def getTags(self):
        """Returns a list of tags that can be added by this plugin
        Returns:
            list of strings
        """
        return {"info-enum4linux-success": Tag("info-enum4linux-success"),
                "high-null-sessions-allowed": Tag("high-null-sessions-allowed", color="red", level="high"),}

    def Parse(self, pentest, file_opened, **kwargs):
        """
        Parse a opened file to extract information
       
        Args:
            file_opened: the open file
            kwargs: not used
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
        cmdline = kwargs.get("cmdline", None)
        tool_m = kwargs.get("tool", None)
        if cmdline is None and tool_m is not None:
            cmdline = tool_m.infos.get("cmdline", None)
        domain, user, password = getUserInfoFromCmdLine(cmdline)
        notes = json.dumps(enum_infos, indent=4)
        if enum_infos is None or not isinstance(enum_infos, dict):
            return PluginResult.empty()
        if enum_infos is not None and enum_infos.get("users") is not None:
            tags = [self.getTags()["info-enum4linux-success"]]
            if domain is None and user is None:
                tags += [Tag(self.getTags()["high-null-sessions-allowed"], notes=f"Null session allowed on {enum_infos.get('ip')}")]
        elif enum_infos.get("null_session_allowed") == True:
            tags += [Tag(self.getTags()["high-null-sessions-allowed"], notes=f"Null or guest session allowed on {enum_infos.get('ip')}")]
        result = PluginResult(notes=notes, tags=tags, lvl="ports", targets={})
        targets = collectEnumResults(pentest, enum_infos, result)
        result.targets = targets
        return result
