"""A plugin to parse nmap httpmethods scan"""

from pollenisator.server.servermodels.defect import ServerDefect
from pollenisator.server.servermodels.ip import ServerIp
from pollenisator.server.servermodels.port import ServerPort
from pollenisator.plugins.plugin import Plugin
import re


def parse(text):
    """
    Args:
        text: raw httpmerhof results
    Returns
        A tuple with 5 values: (every value will be empty if not matching a httpmethods scan)
            0. host scanned
            1. port scanned
            2. proto of the port scanned
            3. service scanned (http or https) 
            4. a list of risky methods found
            5. a list of supported methods found
    Example of output :
Starting Nmap 7.01 ( https://nmap.org ) at 2019-08-06 16:59 CEST
Nmap scan report for httprs.primx.fr (172.22.0.6)
Host is up (0.00040s latency).
rDNS record for 172.22.0.6: autodiscover.primx.fr
PORT    STATE SERVICE
443/tcp open  https
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
MAC Address: 00:E0:81:C1:FD:7E (Tyan Computer)
Nmap done: 1 IP address (1 host up) scanned in 0.95 seconds
    """
    risky_methods = []
    supported_methods = []
    regex_ip = r"Nmap scan report for (\S+)"
    regex_port = r"(\d+)\/(\S+)\s+open\s+(\S+)"
    ip_group = re.search(regex_ip, text)
    if ip_group is None:
        return "", "", "", "", risky_methods, []
    ip = ip_group.group(1).strip()
    port_group = re.search(regex_port, text)
    if port_group is None:
        return "", "", "", "", risky_methods, []
    port = port_group.group(1).strip()
    proto = port_group.group(2).strip()
    service = port_group.group(3).strip()
    lines = text.split("\n")
    for line in lines:
        vuln = line.split("Potentially risky methods: ")
        methods = line.split("Supported Methods: ")
        if len(vuln) == 2:
            risky_methods += set(vuln[1].split(" "))
        if len(methods) == 2:
            supported_methods += set(methods[1].split(" "))
    return ip, port, proto, service, list(risky_methods), list(supported_methods)


class HttpMethods(Plugin):
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
        try:
            notes = file_opened.read().decode("utf-8")
        except UnicodeDecodeError:
            return None, None, None, None
        targets = {}
        tags = []
        if "| http-methods:" not in notes:
            return None, None, None, None
        host, port, proto, service, risky_methods, supported_methods = parse(
            notes)
        if host == "":
            return None, None, None, None
        ServerIp(pentest).initialize(host, infos={"plugin":HttpMethods.get_name()}).addInDb()
        p_o = ServerPort(pentest).initialize(host, port, proto, service, infos={"plugin":HttpMethods.get_name()})
        insert_res = p_o.addInDb()
        if not insert_res["res"]:
            p_o = ServerPort.fetchObject(pentest, {"_id": insert_res["iid"]})

        p_o.updateInfos({"Methods": ", ".join(supported_methods)})
        targets[str(p_o.getId())] = {"ip": host, "port": port, "proto": proto}
        if "TRACE" in risky_methods:
            p_o.addTag("HTTP-TRACE")
            risky_methods.remove("TRACE")
        if len(risky_methods) > 0:
            notes = "RISKY HTTP METHODS ALLOWED : " + " ".join(risky_methods)
            tags = []
            p_o.addTag("RISKY-HTTP-METHODS")
            tags.append("info-http-risky-methods")
        return notes, tags, "port", targets
