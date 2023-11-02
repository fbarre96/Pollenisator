"""A plugin to parse nikto scan"""

from pollenisator.core.components.tag import Tag
from pollenisator.plugins.plugin import Plugin
from pollenisator.server.servermodels.ip import ServerIp
from pollenisator.server.servermodels.port import ServerPort
import re


def parse_nikto_plain_text(output):
    """
    Parse nikto raw result file
        Args:
            output: raw result file content

        Returns:
            a tuple with 4 values:
                0. host 
                1. port
                2. service (http or https)
                3. found infos
    """
    parts = output.split(
        "---------------------------------------------------------------------------")
    host = ""
    host_gr = re.search(r"\+ Target IP:\s+(\S+)", parts[1])
    if host_gr is not None:
        host = host_gr.group(1)
    port = ""
    port_gr = re.search(r"\+ Target Port:\s+(\S+)", parts[1])
    if port_gr is not None:
        port = port_gr.group(1)
    service = "https" if "+ SSL Info:" in parts[1] else "http"
    infos = parts[-2].split("\n+ ")
    if infos:
        infos[0] = infos[0][2:]
    return host, port, service, infos


class Nikto(Plugin):

    default_bin_names = ["nikto", "nikto.pl"]

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
    
    def getTags(self):
        """Returns a list of tags that can be added by this plugin
        Returns:
            list of strings
        """
        return {"todo-nikto": Tag("todo-nikto", "blue", "todo")}

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
        tags = [self.getTags()["todo-nikto"]]
        targets = {}
        try:
            notes = file_opened.read().decode("utf-8")
        except UnicodeDecodeError:
            return None, None, None, None
        if notes == "":
            return None, None, None, None
        if not notes.startswith("- Nikto v"):
            return None, None, None, None
        host, port, service, infos = parse_nikto_plain_text(notes)
        if host:
            if port:
                ServerIp(pentest).initialize(host, infos={"plugin":Nikto.get_name()}).addInDb()
                p_o = ServerPort(pentest).initialize(host, port, "tcp", service, infos={"plugin":Nikto.get_name()})
                insert_res = p_o.addInDb()
                if not insert_res["res"]:
                    p_o = ServerPort.fetchObject(pentest, {"_id": insert_res["iid"]})
                p_o.updateInfos(
                    {"Nikto": infos, "SSL": "True" if service == "https" else "False"})
                targets[str(insert_res["iid"])] = {
                    "ip": host, "port": port, "proto": "tcp"}
        return notes, tags, "port", targets
