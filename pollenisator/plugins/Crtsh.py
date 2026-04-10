"""A plugin to parse a crtsh scan"""

# 1. Imports
import re
from pollenisator.core.components.tag import Tag
from pollenisator.core.models.ip import Ip
from pollenisator.plugins.plugin import Plugin
from pollenisator.plugins.plugin_result import PluginResult, InfoUpdate

def parse_crtsh_line(line):
    """
    Parse one line of crtsh result file
        Args:
            line:  one line of crtsh result file

        Returns:
            Returns the domain found by crtsh on this line or None if no domain exists on this line.
    """
    # Regex checks validity of line and returns DOMAIN ONLY
    regexCrtshLine = r"((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9])\.\s+\d{1,5}\s+IN\s+(CNAME|A)\s+((?:[0-9]{1,3}\.){3}[0-9]{1,3})"
    regexGroups = re.search(regexCrtshLine, line)
    if(regexGroups is not None):  # regex match
        return regexGroups.group(1).strip(), regexGroups.group(2).strip(), regexGroups.group(3).strip()
    return None, None, None


class Crtsh(Plugin):
    default_bin_names = ["crtsh", "crtsh.py"]
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
        return commandExecuted.split(self.getFileOutputArg())[-1].strip()

    def getTags(self):
        """Returns a list of tags that can be added by this plugin
        Returns:
            list of strings
        """
        return {"info-found-domains": Tag("info-found-domains")}

    def Parse(self, pentest, file_opened, **kwargs):
        """
        Parse a opened file to extract information

        foe.test.fr.	801	IN	A	18.19.20.21
        blog.test.fr.	10800	IN	CNAME	22.33.44.55
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
        countFound = 0
        result = PluginResult(tags=tags, lvl="wave", targets={"wave": None})
        for line in file_opened:
            try:
                line = line.decode("utf-8", errors="ignore")
            except UnicodeDecodeError:
                return PluginResult.empty()
            domain, _record_type, ip = parse_crtsh_line(line)
            if domain is not None:
                # a domain has been found
                infosToAdd = {"hostname": ip, "plugin":Crtsh.get_name()}
                ip_m = Ip(pentest).initialize(domain, infos=infosToAdd)
                result.ips.append(ip_m)
                # Also schedule an info update to merge hostname lists for existing IPs
                result.info_updates.append(InfoUpdate(
                    collection="ips",
                    db_key={"ip": domain},
                    infos={"hostname": [ip]}
                ))
                countFound += 1
                notes += domain + " found.\n"
        if notes.strip() == "":
            return PluginResult.empty()
        if countFound != 0:
            tags.append(Tag(self.getTags()["info-found-domains"], notes=str(countFound)))
        result.notes = notes
        result.tags = tags
        return result
