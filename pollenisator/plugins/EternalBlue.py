"""A plugin to parse namp script ms17-010 scan"""

from pollenisator.core.components.tag import Tag
from pollenisator.core.models.ip import Ip
from pollenisator.core.models.port import Port
from pollenisator.plugins.plugin import Plugin
from pollenisator.plugins.plugin_result import PluginResult, TagAddition
import re


class EternalBlue(Plugin):
    default_bin_names = ["nmap"]
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

    def detect_cmdline(self, cmdline):
        """Returns a boolean indicating if this plugin is able to recognize a command line as likely to output results for it.
        Args:
            cmdline: the command line to test
        Returns:
            bool
        """
        result = super().detect_cmdline(cmdline)
        if result and "ms17-010" in cmdline:
            return True
        return False

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
        return {"pwned-eternalblue": Tag("pwned-eternalblue", "red", "high")}


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
        try:
            allnotes = file_opened.read().decode("utf-8", errors="ignore")
        except UnicodeDecodeError:
            return PluginResult.empty()
        regex_ip = r"Nmap scan report for (\S+)"
        ip_group = re.search(regex_ip, allnotes) # no IP is was found
        if ip_group is None:
            return PluginResult.empty()
        # Auto Detect:
        if "smb-vuln-ms17-010:" not in allnotes: # no vuln detected
            return PluginResult.empty()
        # Parsing
        result = PluginResult(notes=allnotes, tags=[], lvl="port", targets=targets)
        sub_notes = allnotes.split("Nmap scan report for")[1:]
        for notes in sub_notes:
            ip = notes.split("\n")[0].strip()
            result.ips.append(Ip(pentest).initialize(ip, infos={"plugin":EternalBlue.get_name()}))
            port_re = r"(\d+)\/(\S+)\s+open\s+microsoft-ds"
            res_search = re.search(port_re, notes)
            if res_search is not None:
                port = res_search.group(1)
                proto = res_search.group(2)
                p_o = Port(pentest)
                p_o.initialize(ip, port, proto, "microsoft-ds", infos={"plugin":EternalBlue.get_name()})
                result.ports.append(p_o)
                targets[str(p_o.getId())] = {
                    "ip": ip, "port": port, "proto": proto}
            if "VULNERABLE" in notes:
                tags = [self.getTags()["pwned-eternalblue"]]
                if res_search is not None:
                    result.tag_additions.append(TagAddition(
                        collection="ports",
                        db_key={"ip": ip, "port": port, "proto": proto},
                        tag=Tag(self.getTags()["pwned-eternalblue"], notes=notes)
                    ))
        result.tags = tags
        result.targets = targets
        return result
