""" A plugin to parse the result of ntds hashes dump """

import os
import re
import shlex
from pollenisator.plugins.plugin import Plugin
from pollenisator.core.components.tag import Tag
from pollenisator.server.modules.activedirectory.users import User
from pollenisator.server.modules.activedirectory.computers import Computer

def parse_output_file_ntds_hashes(nxc_file):
    """Read the given nxc file output and return a dictionary with the hashes
    Args:
        nxc_file (str): The path to the nxc text file to parse
    Returns:
        dict: A dictionary with the hashes
    """

    ### NTDS REGEX PATTERNS ###

    # htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6::: (status=Enabled)
    # Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::: (status=Disabled)
    # krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8::: (status=Disabled)
    # DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::: (status=Disabled)
    # htb.local\$331000-VK4ADACQNUCA:1123:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::: (status=Disabled)
    # htb.local\svc-alfresco:1147:aad3b435b51404eeaad3b435b51404ee:9248997e4ef68ca2bb47ae4e6f128668::: (status=Enabled)
    # zeus:9601:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c::: (status=Enabled)
    # FOREST$:1000:aad3b435b51404eeaad3b435b51404ee:ef4211677e03659b9146755c7aa3d9f6::: (status=Enabled)

    regex_ntds_hashes = re.compile(r"^(\S+):(\d+):(\w+):(\w+):::\s*\(status=(\w+)\)$", re.MULTILINE)

    #----------------------------------------------------------------------------#

    result_dict = {}

    # Chech if the file is empty
    nxc_file.seek(0)
    data = nxc_file.read(1)
    if not bool(data):
        result_dict['error'] = 'Empty file : The command did not return any result'
        return result_dict

    nxc_file.seek(0) # Reset the file pointer to the beginning of the file

    # Parse the file to get the hashes
    for line in nxc_file:
        if isinstance(line, bytes):
            try:
                line = line.decode('utf-8')
            except UnicodeDecodeError:
                result_dict['error'] = 'Error while decoding the file'
                return result_dict

        line = line.strip()

        match = regex_ntds_hashes.match(line)
        if match:
            fulluser = match.group(1)
            print(fulluser)
            if '\\' in fulluser:
                domain = fulluser.split('\\')[0]
                print("domain:", domain)
                username = fulluser.split('\\')[-1]
                print("username:", username)
            else:
                domain = ''
                username = fulluser
            print("fulluser:", fulluser)
            rid = match.group(2)
            hashlm = match.group(3)
            hashnt = match.group(4)
            fullhash = fulluser + ":" + rid + ":" + hashlm + ":" + hashnt + ":::"
            status = match.group(5)

            result_dict[fulluser] = {
                "fulluser": fulluser,
                "domain": domain,
                "username": username,
                "rid": rid,
                "hashlm": hashlm,
                "hashnt": hashnt,
                "fullhash": fullhash,
                "status": status
            }

    return result_dict

class NXCNtds(Plugin):
    """A plugin to parse the result of ntds hashes dump"""

    default_bin_names = ['nxc', 'nxc.exe', 'netexec', 'netexec.exe']
    default_plugin_flags = ["--ntds"]

    def getFileOutputArg(self):
        """ Returns the command line parameter giving the output file
         Returns:
            string
        """
        return " && mv ~/.nxc/logs/*.ntds "

    def getFileOutputExt(self):
        """ Returns the expected file extension for this command result file
            Returns:
                string
            """
        return ".ntds"

    def getFileOutputPath(self, commandExecuted):
        """ Returns the output file path given in the executed command using getFileOutputArg
            Args:
                commandExecuted: the command that was executed with an output file inside.
            Returns:
                string: the path to file created
            """
        return commandExecuted.split(self.getFileOutputArg())[-1].strip().split(" ")[0]

    def getTags(self):
        """ Returns a list of tags that can be added by this plugin
            Returns:
                list of strings
            """
        return {"pwned-ntds": Tag("pwned-ntds", "black", "critical")}

    def Parse(self, pentest, file_opened, **kwargs):
        """
        Parse a opened file to extract information
        Args:
            file_opened: the open file
            kwargs: not used
        Returns:
            Tuple[Optional[str],
                  Optional[List[Tag]],
                  Optionnal[str],
                  Optional[Dict[str, Optional[Dict[str, Optional[str]]]]]
        """

        # Get basic info from command line
        cmdline = kwargs.get("cmdline", None)
        cmd_args = shlex.split(cmdline)
        if len(cmd_args) < 3:
            return None, None, None, None
        ip = cmd_args[2]

        data = parse_output_file_ntds_hashes(file_opened)
        notes = ""
        tags = []
        targets = {}

        # Create a computer object of fetch the existing one
        computer_object = Computer.fetchObject(pentest, {"ip": ip})
        if computer_object is None:
            computer_object = Computer(pentest).initialize(ip=ip)
            computer_object.addInDb()

        for user, item in data.items():
            # Create a user object of fetch the existing one
            user_object = User.fetchObject(pentest, {"username": item["username"]})
            if user_object is None:
                user_object = User(pentest).initialize(username=item["username"],
                                                       domain=item["domain"],
                                                       infos={"RID": item["rid"],
                                                              "hashNT": item["hashnt"], 
                                                              "hashLM": item["hashlm"], 
                                                              "fullhash": item["fullhash"], 
                                                              "status": item["status"]})
                user_object.addInDb()

            # Add the user to the computer
            computer_object.add_user(user_object.domain, user_object.domain, "", user_object.infos)
            computer_object.addInDb()

            # Add the user tag
            tags.append(Tag("pwned-ntds", "black", "critical",
                            notes=f"User {item['username']} found in the NTDS dump"))

            notes += f"User {item['username']} found in the NTDS dump\n"

        # Add the computer tag
        tags.append(Tag("pwned-ntds", "black", "critical",
                        notes=f"Computer {ip} found in the NTDS dump"))

        return notes, tags, "ports", targets
