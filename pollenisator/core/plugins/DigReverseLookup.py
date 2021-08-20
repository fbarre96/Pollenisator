"""A plugin to parse a dig scan"""

from pollenisator.server.ServerModels.Ip import ServerIp
from pollenisator.core.plugins.plugin import Plugin


def parse_reverse_dig(result_dig):
    """
    Parse the results of a reverse lookup by dig
        Args:
            result_dig:  the output of the command dig -x
        Returns:
            Returns the domain found by dig -x as a string or None if no domains was found.
    """
    import re
    regex_ip = r"<<>> -x (\S+)"
    regex = r";; ANSWER SECTION:\s+.*PTR\s+(\S+)."
    ipSearched = re.search(regex_ip, result_dig)
    domainSearch = re.search(regex, result_dig)
    if(domainSearch is not None):  # regex match
        if(ipSearched is not None):  # regex match
            return ipSearched.group(1), domainSearch.group(1)
    return None, None


class DigReverseLookup(Plugin):

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
        return commandExecuted.split(self.getFileOutputArg())[-1].strip()


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
        tags = []
        targets = {}
        ip, domain = parse_reverse_dig(file_opened.read().decode("utf-8"))
        if ip is None:
            return None, None, None, None
        if domain is not None:
            # Add a domain as a scope in db
            ServerIp().initialize(domain).addInDb()
            ip_m = ServerIp().initialize(ip)
            insert_ret = ip_m.addInDb()
            if not insert_ret["res"]:
                ip_m = ServerIp.fetchObject(pentest, {"_id": insert_ret["iid"]})
            hostnames = ip_m.infos.get("hostname", [])
            hostnames = list(set(hostnames + [domain]))
            ip_m.updateInfos({"hostname": hostnames})
            ip_m.notes = "reversed dig give this domain : "+domain+"\n"+ip_m.notes
            notes += "Domain found :"+domain+"\n"
            targets["ip"] = {"ip": ip}
            ip_m.update()
        if notes == "":
            notes = "No domain found\n"
        return notes, tags, "ip", targets
