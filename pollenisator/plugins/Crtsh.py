"""A plugin to parse a crtsh scan"""

# 1. Imports
import re
from pollenisator.server.ServerModels.Ip import ServerIp
from pollenisator.plugins.plugin import Plugin


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

    def Parse(self, pentest, file_opened, **_kwargs):
        """
        Parse a opened file to extract information

        foe.test.fr.	801	IN	A	18.19.20.21
        blog.test.fr.	10800	IN	CNAME	22.33.44.55
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
        tags = []
        countInserted = 0
        for line in file_opened:
            line = line.decode("utf-8")
            domain, _record_type, ip = parse_crtsh_line(line)
            if domain is not None:
                # a domain has been found
                infosToAdd = {"hostname": ip}
                ip_m = ServerIp(pentest).initialize(domain, infos=infosToAdd)
                insert_ret = ip_m.addInDb()
                # failed, domain is out of scope
                if not insert_ret["res"]:
                    notes += domain+" exists but already added.\n"
                    ip_m = ServerIp.fetchObject(pentest, {"_id": insert_ret["iid"]})
                    hostname = ip_m.infos.get("hostname", [])
                    if not isinstance(hostname, list):
                        hostname = [hostname]
                    infosToAdd = {"hostname": list(set([ip] + hostname))}
                    ip_m.updateInfos(infosToAdd)
                else:
                    countInserted += 1
                    notes += domain+" inserted.\n"
        if notes.strip() == "":
            return None, None, None, None
        elif countInserted != 0:
            tags.append("found-domains-info")
        return notes, tags, "wave", {"wave": None}
