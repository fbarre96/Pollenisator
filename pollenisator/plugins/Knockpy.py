"""A plugin to parse knockpy scan"""

from pollenisator.core.components.tag import Tag
from pollenisator.core.models.ip import Ip
from pollenisator.plugins.plugin import Plugin
import re


def parse_knockpy_line(line):
    """
    Parse one line of knockpy result file
        Args:
            line:  one line of knockpy result file

        Returns:
            a tuple with 3 values:
                0. the ip found by knockpy on this line or None if no domain exists on this line.
                1. the domain found by knockpy on this line or None if no domain exists on this line.
                2. a boolean indicating that knockpy marked this domain as alias
    """
    regexIP_domain = r"dns: ((?:\d{1,3}.){3}\d{1,3}) \| \S+//((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9])"
    ipSearch = re.search(regexIP_domain, line)
    ip = None
    domain = None
    if ipSearch is not None:  # regex match
        try:
            ip = ipSearch.group(1).strip()
            domain = ipSearch.group(2).strip()
        except Exception as e:
            raise e
    return ip, domain


class Knockpy(Plugin):
    default_bin_names = ["knockpy.py","knock.py","knock","knockpy"]

    def getFileOutputArg(self):
        """Returns the command line paramater giving the output file
        Returns:
            string
        """
        return " -o /tmp/ > "

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
        return {"info-domains-knockpy": Tag("info-domains-knockpy")}

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
        tags = [self.getTags()["info-domains-knockpy"]]
        marker = "IpaddressCodeSubdomainServerRealhostname"
        markerFound = False
        countFound = 0
        for line in file_opened:
            try:
                line = line.decode("utf-8", errors="ignore")
            except UnicodeDecodeError:
                return None, None, None, None
            if marker == line.replace(" ","").strip():
                markerFound = True
            if not markerFound:
                continue
            ip, domain = parse_knockpy_line(line)
            if ip is not None and domain is not None:
                # a domain has been found
                insert_res = Ip(pentest).initialize(domain, infos={"plugin":Knockpy.get_name()}).addInDb()
                if insert_res["res"]:
                    Ip(pentest).initialize(ip, infos={"plugin":Knockpy.get_name()}).addInDb()
                    notes += f"{domain} inserted ({ip})\n"
                    countFound += 1
                # failed, domain is out of scope
                else:
                    notes += domain+" exists but already added.\n"
        if notes.strip() == "":
            return None, None, None, None
        return notes, tags, "wave", {"wave": None}
