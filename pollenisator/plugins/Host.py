"""A plugin to parse nikto scan"""

from pollenisator.plugins.plugin import Plugin
from pollenisator.server.servermodels.ip import ServerIp
from pollenisator.server.servermodels.port import ServerPort
from pollenisator.server.modules.activedirectory.computers import Computer
from pollenisator.core.components.mongo import MongoClient
import re

def parse_host_plain_text(text):
    regex_host = re.compile(r"^(\S+\.\S+) has address ((?:[0-9]{1,3}\.){3}[0-9]{1,3}$)")
    regex_mail = re.compile(r"^\S+\.\S+ mail is handled by \d+ \S+$")
    ret = {}
    for line in text.split("\n"):
        if line.strip() != "":
            host = re.search(regex_host, line)
            if host is None:
                mail = re.search(regex_mail, line)
                if mail is None:
                    return None
            else:
                domain = host.group(1)
                ip = host.group(2)
                ret[domain] = ip
    return ret


class Host(Plugin):

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
        tags = ["info-host"]
        targets = {}
        try:
            notes = file_opened.read().decode("utf-8")
        except UnicodeDecodeError:
            return None, None, None, None
        if notes == "":
            return None, None, None, None
        infos = parse_host_plain_text(notes)
        if infos is None:
            return None, None, None, None
        for domain, ip in infos.items():
            ServerIp(pentest).initialize(domain, infos={"plugin":Host.get_name()}).addInDb()
            ip_m = ServerIp(pentest).initialize(ip, infos={"plugin":Host.get_name()})
            insert_res = ip_m.addInDb()
            if not insert_res["res"]:
                ip_m = ServerIp.fetchObject(pentest, {"_id": insert_res["iid"]})
            existing_hostnames = ip_m.infos.get("hostname", [])
            if not isinstance(existing_hostnames, list):
                existing_hostnames = [existing_hostnames]
            hostnames = list(set(existing_hostnames + [domain]))
            ip_m.updateInfos({"hostname": hostnames})
            targets["ip"] = {"ip": ip}
            notes += "Domain found :"+domain+"\n"
            if notes == "":
                notes = "No domain found\n"
            # test if the host was on an Active Directory domain name
            active_domain_item = Computer.fetchObject(pentest, {"domain":domain})
            if active_domain_item is not None:
                # host "domain name" gave an answer, probably domain controller
                computer_dc = Computer.fetchObject(pentest, {"ip":ip, "domain":domain})
                if computer_dc is None:
                    Computer(pentest).initialize(pentest, None, name="", ip=ip, domain=domain, infos={"is_dc":True, "plugin":Host.get_name()}).addInDb()
                else:
                    computer_dc.infos.is_dc = True
                    computer_dc.update()
        return notes, tags, "ip", targets
