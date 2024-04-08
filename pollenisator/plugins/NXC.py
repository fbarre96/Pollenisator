"""A plugin to parse a NetExec scan"""

import shlex
from pollenisator.plugins.nxcComponents.NXCBasic import parse_output_file_basic_infos, update_database_basic
from pollenisator.plugins.nxcComponents.NXCKerbrute import parse_output_file_kerbrute, update_database_kerbrute
from pollenisator.plugins.nxcComponents.NXCShares import parse_output_file_shares_infos, update_database_shares
from pollenisator.plugins.nxcComponents.NXCUsers import parse_output_file_user_infos, update_database_users
from pollenisator.plugins.plugin import Plugin
from pollenisator.core.components.tag import Tag

class NXC(Plugin):
    """A plugin to parse a NetExec scan"""

    default_bin_names = ['nxc', 'nxc.exe', 'netexec', 'netexec.exe']

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
        return ".txt"

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
        return {"pwned-" : Tag("pwned-nxc", "red", "high"), 
                "info-nxc-connection-success": Tag("info-nxc-connection-success", "green", "info"),
                "todo-nxc-secrets-found": Tag("todo-nxc-secrets-found", "red", "todo"),
                "todo-lsassy-success": Tag("todo-lsassy-success", "red", "todo"),
                "user-secrets-found": Tag("user-secrets-found", "red", "high"),
                "asreproastable": Tag("asreproastable", "orange", "high"),
                "pwned": Tag("pwned", "red", "high"),
                "signing-disabled": Tag("signing-disabled", "orange", "medium"),
                "smbv1-enabled" : Tag("smbv1-enabled", "orange", "medium"),
                "pwned-ntds": Tag("pwned-ntds", "black", "critical"),
                "hashLM-found": Tag("hashLM-found", "red", "high")}

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

        # Filter on kwargs
        cmdline = kwargs.get("cmdline", None)
        cmd_args = shlex.split(cmdline)

        if "--shares" in cmd_args:
            result_dict = parse_output_file_shares_infos(file_opened)
            if 'error' in result_dict:
                return None, None, None, None
            targets, tags = update_database_shares(pentest, result_dict)

        elif "--users" in cmd_args:
            result_dict = parse_output_file_user_infos(file_opened)
            if 'error' in result_dict:
                return None, None, None, None
            targets, tags = update_database_users(pentest, result_dict)

        elif "-k" in cmd_args or "--asreproast" in cmd_args:
            result_dict = parse_output_file_kerbrute(file_opened)
            if 'error' in result_dict:
                return None, None, None, None
            targets, tags = update_database_kerbrute(pentest, result_dict)

        else:
            result_dict = parse_output_file_basic_infos(file_opened)
            if 'error' in result_dict:
                return None, None, None, None
            targets, tags = update_database_basic(pentest, result_dict)

        # Get all the notes from tags
        notes = ""
        for tag in tags:
            notes += tag.notes + "\n"

        print("notes: ", notes)

        return notes, tags, "ports", targets
