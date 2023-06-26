"""A plugin to parse namp script ms17-010 scan"""

from pollenisator.plugins.plugin import Plugin
from pollenisator.server.servermodels.defect import ServerDefect
from pollenisator.server.servermodels.ip import ServerIp
from pollenisator.server.servermodels.port import ServerPort
import re


class EternalBlue(Plugin):
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

    def Parse(self, pentest, file_opened, **kwargs):
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
        targets = {}
        tags = []
        try:
            notes = file_opened.read().decode("utf-8")
        except UnicodeDecodeError:
            return None, None, None, None
        regex_ip = r"Nmap scan report for (\S+)"
        ip_group = re.search(regex_ip, notes)
        if ip_group is None:
            return None, None, None, None
        # Auto Detect:
        if "smb-vuln-ms17-010:" not in notes:
            return None, None, None, None
        # Parsing
        ip = ip_group.group(1).strip()
        ServerIp(pentest).initialize(ip, infos={"plugin":EternalBlue.get_name()}).addInDb()
        port_re = r"(\d+)\/(\S+)\s+open\s+microsoft-ds"
        res_search = re.search(port_re, notes)
        res_insert = None
        if res_search is None:
            port = None
            proto = None
        else:
            port = res_search.group(1)
            proto = res_search.group(2)
            p_o = ServerPort(pentest)
            p_o.initialize(ip, port, proto, "microsoft-ds", infos={"plugin":EternalBlue.get_name()})
            insert_res = p_o.addInDb()
            res_insert = insert_res["res"]
            targets[str(p_o.getId())] = {
                "ip": ip, "port": port, "proto": proto}
        if "VULNERABLE" in notes:
            tags=["pwned-eternalblue", "red", "high"]
            if res_insert is not None:
                p_o.addTag(("eternalblue", "red", "high"))
        return notes, tags, "port", targets
