"""A plugin to parse bbot scan"""

from pollenisator.core.components.tag import Tag
from pollenisator.core.models.ip import Ip
from pollenisator.plugins.plugin import Plugin
import re
import json


def parse_bbot_line(line):
    """
    Parse one line of bbot result file
    Args:
        line: one line of bbot result file

    Returns:
        A tuple with (domain, ip) or (None, None) if no valid data found
    """
    # Try to parse JSON format first (bbot can output JSON)
    try:
        data = json.loads(line.strip())
        if isinstance(data, dict):
            # Handle JSON output format
            domain = data.get('data', '')
            if 'DNS_NAME' in data.get('type', ''):
                return domain, None
            elif 'IP_ADDRESS' in data.get('type', ''):
                # It's an IP address
                return None, domain
    except (json.JSONDecodeError, ValueError):
        pass
    
    # Try plain text format - just domains/IPs one per line
    line = line.strip()
    if not line or line.startswith('#') or line.startswith('['):
        return None, None
    
    # Check if it's a domain
    domain_pattern = r'^((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9])$'
    domain_match = re.match(domain_pattern, line, re.IGNORECASE)
    if domain_match:
        return domain_match.group(1).lower(), None
    
    # Check if it's an IP address
    ip_pattern = r'^((?:\d{1,3}\.){3}\d{1,3})$'
    ip_match = re.match(ip_pattern, line)
    if ip_match:
        return None, ip_match.group(1)
    
    return None, None


class Bbot(Plugin):
    default_bin_names = ["bbot"]

    def getFileOutputArg(self):
        """Returns the command line parameter giving the output file
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
        Parse an opened file to extract information

        Args:
            pentest: the pentest object
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
        countInserted = 0
        domains_found = set()
        
        for line in file_opened:
            try:
                line = line.decode("utf-8", errors="ignore")
            except UnicodeDecodeError:
                return None, None, None, None
            
            domain, ip = parse_bbot_line(line)
            
            if domain is not None:
                # Avoid duplicates
                if domain in domains_found:
                    continue
                domains_found.add(domain)
                
                # A domain has been found
                infosToAdd = {"plugin": Bbot.get_name()}
                ip_m = Ip(pentest).initialize(domain, infos=infosToAdd)
                insert_ret = ip_m.addInDb()
                
                # failed, domain already exists
                if not insert_ret["res"]:
                    notes += domain + " exists but already added.\n"
                else:
                    countInserted += 1
                    notes += domain + " inserted.\n"
            
            elif ip is not None:
                # An IP address has been found
                infosToAdd = {"plugin": Bbot.get_name()}
                ip_m = Ip(pentest).initialize(ip, infos=infosToAdd)
                insert_ret = ip_m.addInDb()
                
                if not insert_ret["res"]:
                    notes += ip + " exists but already added.\n"
                else:
                    countInserted += 1
                    notes += ip + " inserted.\n"
        
        if notes.strip() == "":
            return None, None, None, None
        elif countInserted != 0:
            tags.append(Tag(self.getTags()["info-found-domains"], notes=str(countInserted)))
        
        return notes, tags, "wave", {"wave": None}
