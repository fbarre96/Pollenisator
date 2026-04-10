"""A plugin to parse subfinder scan"""

from pollenisator.core.components.tag import Tag
from pollenisator.core.models.ip import Ip
from pollenisator.plugins.plugin import Plugin
from pollenisator.plugins.plugin_result import PluginResult
import re


def parseContent(file_opened):
    """
    Parse subfinder output file and return a set of domains found
    Args:
        file_opened: the open file

    Returns:
        A set of domains found or None if parsing failed
    """
    ret = set()
    for line in file_opened:
        try:
            line = line.decode("utf-8", errors="ignore")
        except UnicodeDecodeError:
            return None
        # Match domain pattern
        domainGroup = re.search(
            r"^((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9])$", line.strip())
        if domainGroup is not None:
            # a domain has been found
            domain = domainGroup.group(1)
            ret.add(domain)
    return ret


class Subfinder(Plugin):
    default_bin_names = ["subfinder"]

    def getFileOutputArg(self):
        """Returns the command line paramater giving the output file
        Returns:
            string
        """
        return " -o "

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
            dict of tags
        """
        return {"info-found-domains": Tag("info-found-domains")}

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
        tags = []
        domains = parseContent(file_opened)
        if domains is None:
            return PluginResult.empty()
        
        result = PluginResult(tags=tags, lvl="wave", targets={"wave": None})
        countFound = 0
        for domain in domains:
            infosToAdd = {"plugin": Subfinder.get_name()}
            ip_m = Ip(pentest).initialize(domain.strip(), infos=infosToAdd)
            result.ips.append(ip_m)
            countFound += 1
            notes += domain + " found.\n"
        
        if notes.strip() == "":
            return PluginResult.empty()
        if countFound != 0:
            tags.append(Tag(self.getTags()["info-found-domains"], notes=str(countFound)))
        
        result.notes = notes
        result.tags = tags
        return result
