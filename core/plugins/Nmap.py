"""A plugin to parse nmap scan"""

import re
from server.ServerModels.Ip import ServerIp
from server.ServerModels.Port import ServerPort
from core.plugins.plugin import Plugin


def getIpPortsNmap(pentest, nmapFile):
    """
    Read the given nmap .nmap file results and return a dictionnary with ips and a list of their open ports.
        Args:
            nmapFile:  the path to the .nmap file generated by an nmap scan

        Returns:
            notes about inseted ip and ports
    """
    notes = ""
    countOpen = 0
    all_text = nmapFile.read().decode("utf-8").strip()
    lines = all_text.split("\n")
    if len(lines) <= 3:
        # print("Not enough lines to be nmap")
        return None
    if not lines[0].startswith("# Nmap"):
        # print("Not starting with # Nmap")
        return None
    if "scan initiated" not in lines[0]:
        # print("Not scan initiated on first line")
        return None
    if "# Nmap done at" not in lines[-1]:
        # print("Not # Nmap done at at the end : "+str(lines[-1]))
        return None
    ipCIDR_m = None
    ipDom_m = None
    for line in lines:
        # Search ip in file
        # match an ip
        ip = re.search(
            r"^Nmap scan report for (\S+)(?: \(((?:[0-9]{1,3}\.){3}[0-9]{1,3})\))?$", line)
        if ip is not None:  # regex match
            lastIp = [ip.group(1), ip.group(
                2) if ip.group(2) is not None else ""]
            notes_ip = "ip:" + \
                str(lastIp[1]) if lastIp[1] != "" and lastIp[1] is not None else ""
            ipCIDR_m = ServerIp(pentest).initialize(str(lastIp[0]), notes=notes_ip)
            if lastIp[1].strip() != "" and lastIp[1] is not None:
                ipDom_m = ServerIp(pentest).initialize(
                    str(lastIp[1]), notes="domain:"+str(lastIp[0]))
                
            else:
                ipDom_m = None
        if " open " in line:
            if ipCIDR_m is None:  # Probably a gnmap
                return None
            notes += line+"\n"
            # regex to find open ports in gnmap file
            port_search = re.search(
                r"^(\d+)\/(\S+)\s+open\s+(\S+)(?: +(.+))?$", line)
            if port_search is not None:
                port_number = str(port_search.group(1))
                proto = str(port_search.group(2))
                service = "unknown" if str(port_search.group(
                    3)) == "" else str(port_search.group(3))
                product = str(port_search.group(4))
                # a port unique key is its protocole/number.
                countOpen += 1
                validIps = []
                if ipCIDR_m is not None:
                    ipCIDR_m.addInDb()
                    validIps.append(ipCIDR_m.ip)
                    if ipDom_m is not None:
                        insert_res = ipDom_m.addInDb()
                        if not insert_res["res"]:
                            ipDom_m = ServerIp.fetchObject(pentest, {"_id": insert_res["iid"]})
                        ipDom_m.updateInfos({"hostname": list(set(list(ipDom_m.infos.get(
                            "hostname", []))+[str(ipCIDR_m.ip)]))})
                        validIps.append(ipDom_m.ip)
                for ipFound in validIps:
                    if ip == "":
                        continue
                    port_o = ServerPort(pentest).initialize(ipFound, port_number, proto, service, product)
                    insert_res = port_o.addInDb()
                    if not insert_res["res"]:
                        port_o = ServerPort.fetchObject(pentest, {"_id": insert_res["iid"]})
                    port_o.service = service
                    port_o.update()

    notes = str(countOpen)+" open ports found\n"+notes
    return notes


class Nmap(Plugin):
    def getFileOutputArg(self):
        """Returns the command line paramater giving the output file
        Returns:
            string
        """
        return " -oN "

    def getFileOutputExt(self):
        """Returns the expected file extension for this command result file
        Returns:
            string
        """
        return ".nmap"

    def getFileOutputPath(self, commandExecuted):
        """Returns the output file path given in the executed command using getFileOutputArg
        Args:
            commandExecuted: the command that was executed with an output file inside.
        Returns:
            string: the path to file created
        """
        return (commandExecuted.split(self.getFileOutputArg())[-1].strip().split(" ")[0])+".nmap"


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
        tags = []
        notes = getIpPortsNmap(pentest, file_opened)
        if notes is None:
            return None, None, None, None
        return notes, tags, "scope", {}
