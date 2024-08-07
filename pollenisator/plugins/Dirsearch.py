"""A plugin to parse a dirsearch scan"""

from abc import abstractmethod
from typing import IO, Any, Tuple, Optional, List, Dict, cast
from pollenisator.core.components.tag import Tag
from pollenisator.core.models.ip import Ip
from pollenisator.core.models.port import Port
from pollenisator.plugins.plugin import Plugin
import re


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
    default_bin_names = ["dirsearch","dirsearch.py"]

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


    def getTags(self):
        """Returns a list of tags that can be added by this plugin
        Returns:
            list of strings
        """
        return {"todo-dirsearch": Tag("todo-dirsearch", "blue", "todo")}

    @abstractmethod
    def Parse(self, pentest: str, file_opened: IO[bytes], **kwargs: Any) -> Tuple[Optional[str], Optional[List[Tag]], Optional[str], Optional[Dict[str, Optional[Dict[str, Optional[str]]]]]]:
        """
        Parse an opened file to extract information.

        Args:
            pentest (str): The name of the pentest.
            file_opened (BinaryIO): The opened file.
            **kwargs (Any): Additional parameters (not used).

        Returns:
            Tuple[Optional[str], Optional[List[Tag]], Optional[str], Optional[Dict[str, Dict[str, str]]]]: A tuple with 4 values (All set to None if Parsing wrong file): 
                0. notes (str): Notes to be inserted in tool giving direct info to pentester.
                1. tags (List[Tag]): A list of tags to be added to tool.
                2. lvl (str): The level of the command executed to assign to given targets.
                3. targets (Dict[str, Optional[Dict[str, Optional[str]]]]]): A list of composed keys allowing retrieve/insert from/into database targeted objects.
        """
        tags = []
        try:
            data = file_opened.read().decode("utf-8", errors="ignore")
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
                ip_m = Ip(pentest).initialize(host, infos={"plugin":Dirsearch.get_name()})
                ip_m.addInDb()
                for port in hosts[host]:
                    port_o = Port(pentest)
                    port_o.initialize(host, port, "tcp",
                                      hosts[host][port]["service"], infos={"plugin":Dirsearch.get_name()})
                    insert_ret = port_o.addInDb()
                    if not insert_ret["res"]:
                        port_db = Port.fetchObject(pentest, {"_id": insert_ret["iid"]})
                        if port_db is not None:
                            port_o = cast(Port, port_db)
                        else:
                            continue
                    targets[str(port_o.getId())] = port_o.getDbKey()
                    hosts[host][port]["paths"].sort(key=lambda x: int(x[0]))
                    results = "\n".join(hosts[host][port]["paths"])
                    notes += results
                    newInfos = {}
                    atLeastOne = False
                    for statuscode in hosts[host][port]:
                        if isinstance(statuscode, int):
                            if hosts[host][port].get(statuscode, []):
                                newInfos["Dirsearch_"+str(statuscode)
                                        ] = hosts[host][port][statuscode]
                        else:
                            atLeastOne = True
                    newInfos["SSL"] = "True" if hosts[host][port]["service"] == "https" else "False"
                    port_o.updateInfos(newInfos)
                    if atLeastOne:
                        tags = [Tag(self.getTags()["todo-dirsearch"], notes=notes)]
        return notes, tags, "port", targets
