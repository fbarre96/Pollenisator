"""A plugin to parse namp script ms17-010 scan"""

from pollenisator.core.plugins.plugin import Plugin
from pollenisator.server.ServerModels.Defect import ServerDefect
from pollenisator.server.ServerModels.Ip import ServerIp
from pollenisator.server.ServerModels.Port import ServerPort
import re


class EternalBlue(Plugin):
    def getFileOutputArg(self):
        """Returns the command line paramater giving the output file
        Returns:
            string
        """
        return " > "

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
        notes = file_opened.read().decode("utf-8")
        regex_ip = r"Nmap scan report for (\S+)"
        ip_group = re.search(regex_ip, notes)
        if ip_group is None:
            return None, None, None, None
        # Auto Detect:
        if "smb-vuln-ms17-010:" not in notes:
            return None, None, None, None
        # Parsing
        ip = ip_group.group(1).strip()
        ServerIp().initialize(ip).addInDb()
        port_re = r"(\d+)\/(\S+)\s+open\s+microsoft-ds"
        res_search = re.search(port_re, notes)
        res_insert = None
        if res_search is None:
            port = None
            proto = None
        else:
            port = res_search.group(1)
            proto = res_search.group(2)
            p_o = ServerPort()
            p_o.initialize(ip, port, proto, "microsoft-ds")
            insert_res = p_o.addInDb()
            res_insert = insert_res["res"]
            targets[str(p_o.getId())] = {
                "ip": ip, "port": port, "proto": proto}
        if "VULNERABLE" in notes:
            d_o = ServerDefect()
            d_o.initialize(ip, port, proto, "EternalBlue",
                           "Difficult", "Critical", "Critical", "N/A", ["Base"], notes=notes, proofs=[])
            d_o.addInDb()
            tags=["P0wned!"]
            if res_insert is not None:
                p_o.addTag("P0wned!")
        return notes, tags, "port", targets
