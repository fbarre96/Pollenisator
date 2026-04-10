"""A plugin to parse nikto scan"""

from pollenisator.core.components.tag import Tag
from pollenisator.core.models.ip import Ip
from pollenisator.core.models.port import Port
from pollenisator.plugins.plugin import Plugin
from pollenisator.plugins.plugin_result import PluginResult, InfoUpdate
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
        tags = [self.getTags()["todo-nikto"]]
        targets = {}
        try:
            notes = file_opened.read().decode("utf-8", errors="ignore")
        except UnicodeDecodeError:
            return PluginResult.empty()
        if notes == "":
            return PluginResult.empty()
        if not notes.startswith("- Nikto v"):
            return PluginResult.empty()
        result = PluginResult(notes=notes, tags=tags, lvl="port", targets=targets)
        host, port, service, infos = parse_nikto_plain_text(notes)
        if host:
            if port:
                result.ips.append(Ip(pentest).initialize(host, infos={"plugin": Nikto.get_name()}))
                result.ports.append(Port(pentest).initialize(host, port, "tcp", service, infos={"plugin": Nikto.get_name()}))
                result.info_updates.append(InfoUpdate(
                    collection="ports",
                    db_key={"ip": host, "port": port, "proto": "tcp"},
                    infos={"Nikto": infos, "SSL": "True" if service == "https" else "False"}
                ))
                targets["nikto_target"] = {"ip": host, "port": port, "proto": "tcp"}
        return result
