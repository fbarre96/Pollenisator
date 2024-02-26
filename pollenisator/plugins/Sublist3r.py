"""A plugin to parse sublist3r"""

from pollenisator.core.components.tag import Tag
from pollenisator.core.models.ip import Ip
from pollenisator.plugins.plugin import Plugin
import re

def parseContent(file_opened):
    ret = set()
    for line in file_opened:
        try:
            line = line.decode("utf-8", errors="ignore")
        except UnicodeDecodeError:
            return None
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
    default_bin_names = ["sublister", "sublister.py","sublist3r", "sublist3r.py"]
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


    def getTags(self):
        """Returns a list of tags that can be added by this plugin
        Returns:
            list of strings
        """
        return {"info-domains-sublist3r": Tag("info-domains-sublist3r")}

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
        tags = [self.getTags()["info-domains-sublist3r"]]
        ret = parseContent(file_opened)
        if ret is None:
            return None, None, None, None
        for domain in ret:
            insert_res = Ip(pentest).initialize(domain.strip(), infos={"plugin":Sublist3r.get_name()}).addInDb()
            # failed, domain is out of wave, still noting thi
            if not insert_res["res"]:
                notes += domain+" exists but already added.\n"
            else:
                notes += domain+" inserted.\n"
        if notes.strip() == "":
            return None, None, None, None
        return notes, tags, "wave", {"wave": None}
