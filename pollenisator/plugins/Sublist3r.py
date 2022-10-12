"""A plugin to parse sublist3r"""

from pollenisator.plugins.plugin import Plugin
from pollenisator.server.ServerModels.Ip import ServerIp
import re

def parseContent(file_opened):
    ret = set()
    for line in file_opened:
        line = line.decode("utf-8")
        domainGroup = re.search(
            r"((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9])", line.strip())
        if domainGroup is not None:
            # a domain has been found
            domain = domainGroup.group(1)
            if line.strip() != domain.strip():
                return set()
            ret.add(domain)
        else:
            return set()
    return ret

class Sublist3r(Plugin):
    def getFileOutputArg(self):
        """Returns the command line paramater giving the output file
        Returns:
            string
        """
        return " -n -o "

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


    

    def Parse(self, pentest, file_opened, **_kwargs):
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
        notes = ""
        tags = ["found-domains-info"]
        ret = parseContent(file_opened)
        for domain in ret:
            insert_res = ServerIp().initialize(domain.strip()).addInDb()
            # failed, domain is out of wave, still noting thi
            if not insert_res["res"]:
                notes += domain+" exists but already added.\n"
            else:
                notes += domain+" inserted.\n"
        if notes.strip() == "":
            return None, None, None, None
        return notes, tags, "wave", {"wave": None}
