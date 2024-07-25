"""A plugin to parse a NetExec SpiderPlus module scan"""

import json
import os
import shlex
from typing import cast
from pollenisator.plugins.plugin import Plugin
from pollenisator.core.components.tag import Tag
from pollenisator.server.modules.activedirectory.shares import Share

def convert_size(size):
    """Convert size to bytes
    Args:
        size: the size to convert
    Returns:
        int: the size in bytes
    """
    if size[-2:] == " B":
        return float(size[:-2])
    if size[-2:] == "KB":
        return float(size[:-2]) * 1024
    if size[-2:] == "MB":
        return float(size[:-2]) * 1024 * 1024
    if size[-2:] == "GB":
        return float(size[:-2]) * 1024 * 1024 * 1024
    if size[-2:] == "TB":
        return float(size[:-2]) * 1024 * 1024 * 1024 * 1024
    if size[-2:] == "PB":
        return float(size[:-2]) * 1024 * 1024 * 1024 * 1024 * 1024
    return 0

class NXCSpiderPlus(Plugin):
    """A plugin to parse a NetExec SpiderPlus module scan"""

    default_bin_names = ['nxc', 'nxc.exe', 'netexec', 'netexec.exe']
    default_plugin_flags = ["-M", "spider_plus"]

    def getFileOutputArg(self):
        """Returns the command line parameter giving the output file
        Returns:
            string
        """

        return " -o OUTPUT_FOLDER=./ && mv *.json "

    def getFileOutputExt(self):
        """Returns the expected file extension for this command result file
        Returns:
            string
        """
        return ".json"

    def getFileOutputPath(self, commandExecuted):
        """Returns the output file path given in the executed command using getFileOutputArg
        Args:
            commandExecuted: the command that was executed with an output file inside.
        Returns:
            string: the path to file created
        """

        ip = commandExecuted.split(" ")[2]

        path = commandExecuted.split(self.getFileOutputArg())[-1].strip().split(" ")[0]

        if path[-1] == "/":
            path = path[:-1]

        print(f"Path: {path} IP: {ip}")

        return f"{path}/{ip}"

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
            Tuple[Optional[str], 
                  Optional[List[Tag]], 
                  Optional[str], 
                  Optional[Dict[str, Optional[Dict[str, Optional[str]]]]]: 
        """
        # Get the ip address form the command line
        cmdline = kwargs.get("cmdline", None)
        cmd_args = shlex.split(cmdline)
        if len(cmd_args) < 3:
            return None, None, None, None
        ip = cmd_args[2]

        # Get the user and password from the command line
        for index, arg in enumerate(cmd_args):
            if arg == "-u":
                username = cmd_args[index + 1]

        data = json.load(file_opened)
        notes = ""
        tags = []
        targets = {}

        for share in data.items():
            share_name = share[0]

            # Create the share object and add it in DB
            share_object = Share(pentest).initialize(ip, share_name)
            insert_ret = share_object.addInDb()
            if not insert_ret["res"]:
                share_db = Share.fetchObject(pentest, {"_id": insert_ret["iid"]})
                if share_db is not None:
                    share_object = cast(Share, share_db)
                else:
                    continue

            # Update share with sharefiles
            for share_content in share[1].items():
                file_path = share_content[0]
                file_size = convert_size(share_content[1]["size"])
                file_info = share_content[1]
                user_domain = file_path.split("/")[0]

                # Add file to Share object
                share_object.add_file(path=file_path, flagged=None, priv="READ", size=file_size, domain=user_domain, user=username, infos=file_info)

                # Create Tag
                sharefile_tag = Tag("todo-nxc-sharefile-found", "green", "todo", notes=f"Found file in {share_name} share with {username} user.")
                share_object.addTag(sharefile_tag)

            # Update share in DB
            share_object.update(insert_ret["iid"])

        return notes, tags, "shares", targets
