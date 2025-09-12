"""A plugin to parse getuserspn from impacket scan"""

import shlex
from pollenisator.core.components.tag import Tag
from pollenisator.core.models.ip import Ip
from pollenisator.plugins.plugin import Plugin
from pollenisator.server.modules.activedirectory.computers import Computer
import re

from pollenisator.server.modules.activedirectory.users import User


class GetUserSPNImpacket(Plugin):
    default_bin_names = ["GetUserSPNs.py","GetUserSPNs"]
    def getFileOutputArg(self):
        """Returns the command line paramater giving the output file
        Returns:
            string
        """
        return " -outputfile "

    def getFileOutputExt(self):
        """Returns the expected file extension for this command result file
        Returns:
            string
        """
        return ".txt"

    def getFileOutputPath(self, commandExecuted):
        """Returns the output file path given in the executed command using getFileOutputArg
        Args:
            commandExecuted: the command that was executed with an output file inside.
        Returns:
            string: the path to file created
        """
        return commandExecuted.split(self.getFileOutputArg())[-1].strip().split(" ")[0]
    
    def changeCommand(self, command, outputDir, toolname):
        """
        Summary: Complete the given command with the tool output file option and filename absolute path.
        Args:
            * command : the command line to complete
            * outputDir : the directory where the output file must be generated
            * toolname : the tool name (to be included in the output file name)
        Return:
            The command completed with the tool output file option and filename absolute path.
        """
        # default is append at the end
        if self.getFileOutputArg() not in command:
            parts = shlex.split(command) 
            parts.insert(1, self.getFileOutputArg()+outputDir+toolname)
            return " ".join(parts)
        return command
    
    def getTags(self):
        """Returns a list of tags that can be added by this plugin
        Returns:
            list of strings
        """
        return {"kerberoastable": Tag("kerberoastable", "red", "high"),}

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
        
        targets = {}
        tags = []
        notes = ""
        try:
            notes = file_opened.read().decode("utf-8", errors="ignore")
        except UnicodeDecodeError:
            return None, None, None, None
        if notes == "":
            return None, None, None, None
        for line in notes.split("\n"):
            line = line.strip()
            if line.startswith("$krb5t"):
                # ticket found
                tags.append(self.getTags()["kerberoastable"])
                hash_parts = line.split("$")
                try:
                    domain = hash_parts[5].split("/")[0].lower()
                    username = "/".join(hash_parts[5].split("/")[1:]).lower()
                    if username.endswith("*"):
                        username = username[:-1]
                    hash_kerb = line.strip()
                    notes += f"User {domain}\\{username} has a Kerberoastable SPN hash: {hash_kerb}"
                    user_m =  User.fetchObject(pentest, {"username": username, "domain": domain})
                    if user_m is None:
                        user_m = User(pentest).initialize(domain, username, "", None, None, infos={"plugin":GetUserSPNImpacket.get_name(), "secrets":[hash_kerb]})
                        user_m.addInDb()
                        user_m.addTag(self.getTags()["kerberoastable"])

                    else:
                        secrets = user_m.infos.get("secrets", [])
                        if secrets is None:
                            secrets = []
                        if hash_kerb not in secrets:
                            secrets.append(hash_kerb)
                        user_m.infos["secrets"] = secrets
                        user_m.update()
                        user_m.addTag(self.getTags()["kerberoastable"])
                except IndexError:
                    continue

        return notes, tags, "user", targets
