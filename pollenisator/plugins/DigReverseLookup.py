"""A plugin to parse a dig scan"""

from pollenisator.core.models.ip import Ip
from pollenisator.plugins.plugin import Plugin
from pollenisator.plugins.plugin_result import PluginResult, InfoUpdate

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
    default_bin_names = ["dig"]
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
        targets = {}
        try:
            ip, domain = parse_reverse_dig(file_opened.read().decode("utf-8", errors="ignore"))
        except UnicodeDecodeError:
            return PluginResult.empty()
        if ip is None:
            return PluginResult.empty()
        if domain is not None:
            result = PluginResult(notes=notes, tags=tags, lvl="ip", targets=targets)
            # Add domain as an IP entry
            result.ips.append(Ip(pentest).initialize(domain, infos={"plugin": DigReverseLookup.get_name()}))
            # Add the IP entry with hostname info
            result.ips.append(Ip(pentest).initialize(ip, infos={"plugin": DigReverseLookup.get_name(), "hostname": [domain]}))
            # Deferred info update to merge hostname into the IP entry
            result.info_updates.append(InfoUpdate(
                collection="ips",
                db_key={"ip": ip},
                infos={"hostname": [domain], "plugin": DigReverseLookup.get_name()}
            ))
            notes += "Domain found :" + domain + "\n"
            notes += "reversed dig give this domain : " + domain + "\n"
            targets["ip"] = {"ip": ip}
            result.notes = notes
            return result
        notes = "No domain found\n"
        return PluginResult(notes=notes, tags=tags, lvl="ip", targets=targets)
