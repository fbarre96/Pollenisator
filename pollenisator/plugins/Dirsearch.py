"""A plugin to parse a dirsearch scan"""

from pollenisator.plugins.plugin import Plugin
from pollenisator.server.servermodels.ip import ServerIp
from pollenisator.server.servermodels.port import ServerPort
import re
import os


def parse_dirsearch_file(notes):
    """Parse a dirsearch resulting raw text file
    Args:
        notes: the dirsearch raw text
    Returns:
        a dict with scanned hosts has keys and another dict as value:
            this dict has scanned ports as keys and another dict as value:
                this dict has 3 keys:
                    * service: "http" or "https"
                    * paths: a list of path found on port
                    * statuscode: a list of status code matching the list of paths
    """
    hosts = {}
    parsed = []
    lines = notes.split("\n")
    for line in lines:
        words = line.strip().split()
        res = []
        for word in words:
            if word.strip() != "":
                res.append(word.strip())
        if len(res) == 3:
            parsed.append(res)
    for pathFound in parsed:
        # Auto detect and infos extract
        try:
            # integer conversion fails if not valid
            statuscode = int(pathFound[0])
        except ValueError:
            continue
        if re.search(r"\d+K?M?B", pathFound[1]) is None:
            continue
        url = pathFound[2]
        re_host_port = r"http.?:\/\/([^\/]+)(\/.*)?"
        service = "https" if "https://" in url else "http"
        host_port = re.search(re_host_port, url)
        if host_port is not None:
            infos = host_port.group(1).split(":")
            if len(infos) == 2:
                host = infos[0]
                port = infos[1]
            elif len(infos) == 1:
                host = infos[0]
                port = "443" if service == "https" else "80"
            elif len(infos) > 2:
                host = "/".join(infos[:-1])
                port = infos[-1]
            if host not in hosts:
                hosts[host] = {}
            if port not in hosts[host]:
                hosts[host][port] = {}
            hosts[host][port]["service"] = service
            hosts[host][port]["paths"] = hosts[host][port].get(
                "paths", [])+["   ".join(pathFound)]
            hosts[host][port][statuscode] = hosts[host][port].get(
                statuscode, [])+[host_port.group(2)]
        else:
            print("Not a url: "+str(pathFound[2]))

    return hosts


class Dirsearch(Plugin):

    def __init__(self):
        """Constructor"""
        self.port_m = None


    def getFileOutputArg(self):
        """Returns the command line paramater giving the output file
        Returns:
            string
        """
        return " --format=plain -o "

    def getFileOutputExt(self):
        """Returns the expected file extension for this command result file
        Returns:
            string
        """
        return ".txt"

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
        tags = []
        try:
            data = file_opened.read().decode("utf-8")
        except UnicodeDecodeError:
            return None, None, None, None
        notes = ""
        if data.strip() == "":
            return None, None, None, None
        else:
            hosts = parse_dirsearch_file(data)
            if not hosts.keys():
                return None, None, None, None
            targets = {}
            for host in hosts:
                ServerIp(pentest).initialize(host, infos={"plugin":Dirsearch.get_name()}).addInDb()
                for port in hosts[host]:
                    port_o = ServerPort(pentest)
                    port_o.initialize(host, port, "tcp",
                                      hosts[host][port]["service"], infos={"plugin":Dirsearch.get_name()})
                    insert_ret = port_o.addInDb()
                    if not insert_ret["res"]:
                        port_o = ServerPort.fetchObject(pentest, {"_id": insert_ret["iid"]})
                    targets[str(port_o.getId())] = {
                        "ip": host, "port": port, "proto": "tcp"}
                    hosts[host][port]["paths"].sort(key=lambda x: int(x[0]))
                    results = "\n".join(hosts[host][port]["paths"])
                    notes += results
                    newInfos = {}
                    atLeastOne = False
                    for statuscode in hosts[host][port]:
                        if isinstance(statuscode, int):
                            if statuscode != 404:
                                if hosts[host][port].get(statuscode, []):
                                    newInfos["Dirsearch_"+str(statuscode)
                                            ] = hosts[host][port][statuscode]
                        else:
                            atLeastOne = True
                    newInfos["SSL"] = "True" if hosts[host][port]["service"] == "https" else "False"
                    port_o.updateInfos(newInfos)
                    if atLeastOne:
                        tags = ["todo-dirsearch"]
        return notes, tags, "port", targets
