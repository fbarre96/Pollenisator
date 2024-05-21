"""A plugin to parse the output of feroxbuster tool"""

from abc import abstractmethod
from typing import Any, Dict, IO, List, Optional, Tuple, cast
from pollenisator.core.models.ip import Ip
from pollenisator.core.models.port import Port
from pollenisator.core.components.tag import Tag
from pollenisator.plugins.plugin import Plugin


def parse_ferox_file(notes):
    """Parse a feroxbuster output file
    Args:
        notes (str): The feroxbuster raw output text
    Returns:
        hosts: dict of scanned hosts as keys and another dict as values containing :
            - services: "http" or "https" (str)
            - paths: list of paths found (List[str])
            - status: list of status codes matching the paths (List[int])
            - responses: list of dicts containing theses informations about the response :
                - path: the path (str)
                - status: the status code (int)
                - lines: the number of lines in the response (int)
                - words: the number of words in the response (int)
                - chars: the number of characters in the response (int)
                - redirect: the redirect location if any (str)
    """

    hosts = {}

    # Split the notes into lines and iterate over them
    lines = notes.split("\n")
    for line in lines:
        if line == "":                                      # Skip empty lines
            continue
        list_keywords = line.split()                        # Split the line into words
        status = int(list_keywords[0])                      # The 1st word is the status code
        #method = list_keywords[1]                           # The 2nd word is the method used
        lines = int(list_keywords[2].replace("l", ""))      # The 3rd word is number of lines
        words = int(list_keywords[3].replace("w", ""))      # The 4th word is number of words
        chars = int(list_keywords[4].replace("c", ""))      # The 5th word is number of characters
        url = list_keywords[5]                              # The 6th word is the URL
        service = url.split("://")[0]                       # Get the service from the URL
        host = url.split("://")[1].split("/")[0]            # Get the host from the URL
        path = url.split(host)[1]                           # Get the path from the URL

        # Detect if port is in url
        if ":" in host:
            host, port = host.split(":")[0], host.split(":")[1]
        else:
            port = 80 if service == "http" else 443

        if host not in hosts:       # If the host is not in the hosts dict, add it
            hosts[host] = {
                "service": service,
                "port": port,
                "paths": [],
                "status": [],
                "responses": []
            }

        if hosts[host]["responses"] == []:  # If the responses list is empty, add the first response
            hosts[host]["responses"].append({
                "path": path,
                "status": status,
                "lines": lines,
                "words": words,
                "chars": chars,
            })
            hosts[host]["paths"].append(path)            # Add the path to the paths list
            hosts[host]["status"].append(status)         # Add the status to the status list
            if "=> " in line:
                hosts[host]["responses"][0]["redirect"] = line.split("=> ")[1]

        for i in range(len(hosts[host]["responses"])):
            if words > hosts[host]["responses"][i]["words"]:
                hosts[host]["responses"].insert(i, {        # Add the response to the responses list
                    "path": path,
                    "status": status,
                    "lines": lines,
                    "words": words,
                    "chars": chars,
                })
                hosts[host]["paths"].insert(i, path)        # Add the path to the paths list
                hosts[host]["status"].insert(i, status)     # Add the status to the status list

                if "=> " in line:
                    hosts[host]["responses"][i]["redirect"] = line.split("=> ")[1]

                break

            if i == len(hosts[host]["responses"]) - 1:
                hosts[host]["responses"].append({        # Add the response to the responses list
                    "path": path,
                    "status": status,
                    "lines": lines,
                    "words": words,
                    "chars": chars,
                })
                hosts[host]["paths"].append(path)        # Add the path to the paths list
                hosts[host]["status"].append(status)    # Add the status to the status list
                if "=> " in line:
                    hosts[host]["responses"][i]["redirect"] = line.split("=> ")[1]

    return hosts

class Ferox(Plugin):
    """Class represeting the feroxbuster plugin"""

    default_bin_names = ["feroxbuster"]

    def __init__(self):
        """Constructor"""
        self.port_object = None

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
        return {"todo-ferox": Tag("todo-ferox", "blue", "todo"),
                "todo-ferox-200": Tag("todo-ferox-200", "blue", "todo")}

    @abstractmethod
    def Parse(self, pentest: str, file_opened: IO[bytes], **kwargs: Any) -> Tuple[Optional[str], Optional[List[Tag]], Optional[str], Optional[Dict[str, Optional[Dict[str, Optional[str]]]]]]:
        """
        Parse an openned feroxbuster output file to extract information

        Args:
            pentest (str): the pentest name
            file_opened (BinaryIO): the file opened
            **kwargs (Any): additional arguments

        Returns:
            Tuple[Optional[str], 
                  Optional[List[Tag]], 
                  Optional[str], 
                  Optional[Dict[str, Optional[Dict[str, Optional[str]]]]]]: 

                    - notes (str): Notes to be added in tool giving direct info to pentester
                    - tags (List[Tag]): Tags to be added to the tool
                    - lvl (str): The level of the command executed to assign to given targets
                    - hosts (Dict[str, Optional[Dict[str, Optional[str]]]): 
                        Dict of composed keys allowing retrieve/insert from/into DB targeted objects
        """
        tags = []   # List of tags to be added to the tool
        notes = ""  # Notes to be added in tool giving direct info to pentester

        try:
            data = file_opened.read().decode("utf-8", errors="ignore") # Read the file
        except UnicodeDecodeError:
            return None, None, None, None

        if data.strip() == "":              # If the file is empty, return None
            return None, None, None, None

        hosts = parse_ferox_file(data)
        if not hosts.keys():            # If the hosts dict is empty, return None
            return None, None, None, None

        targets = {}    # The targets dict
        for host in hosts:
            ip_object = Ip(pentest)
            ip_object.initialize(host, infos={"plugin": Ferox.get_name()})

            insert_ret = ip_object.addInDb() # Add the Ip object to the database
            if not insert_ret["res"]:        # If the insertion failed, fetch the object from the DB
                ip_db = Ip.fetchObject(pentest, {"_id": insert_ret["iid"]})
                if ip_db is not None:
                    ip_object = cast(Ip, ip_db)
                else:
                    continue

            # Add the port to the database
            port = hosts[host]["port"]
            port_object = Port(pentest)
            port_object.initialize(host, port, "tcp", hosts[host]["service"], infos={"plugin": Ferox.get_name()})

            insert_ret = port_object.addInDb() # Add the Port object to the database
            if not insert_ret["res"]:          # If the insertion failed, fetch the object from DB
                port_db = Port.fetchObject(pentest, {"_id": insert_ret["iid"]})
                if port_db is not None:
                    port_object = cast(Port, port_db)
                else:
                    continue

            targets[str(port_object.getId())] = port_object.getDbKey() # Add the to the targets dict

            # Add status code, host and path of the current host to the notes
            results = "\n"
            for status, path, response in zip(hosts[host]["status"], hosts[host]["paths"], hosts[host]["responses"]):
                results += f"""{status} - {host} - {path} - #Words: {response["words"]}\n"""
            notes += results

            # Check if the connection is SSL or not
            new_infos = {}
            new_infos["SSL"] = "True" if hosts[host]["service"] == "https" else "False"
            port_object.updateInfos(new_infos)

            # Add the tags to the list of tags if there is at least one path
            if len(hosts[host]["paths"]) > 0:
                tag = self.getTags()["todo-ferox"]
                tag.notes = notes
                tags.append(tag)

        return notes, tags, "port", targets
