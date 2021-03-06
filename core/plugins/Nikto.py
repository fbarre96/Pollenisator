"""A plugin to parse nikto scan"""

from core.plugins.plugin import Plugin
from server.ServerModels.Ip import ServerIp
from server.ServerModels.Port import ServerPort
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
    def __init__(self):
        self.toolmodel = None

    def getActions(self, toolmodel):
        """
        Summary: Add buttons to the tool view.
        Args:
            * toolmodel : the tool model opened in the pollenisator client.
        Return:
            A dictionary with buttons text as key and function callback as value.
        """
        self.toolmodel = toolmodel
        return {"Open in browser": self.openInBrowser}

    def openInBrowser(self, _event=None):
        """Callback of action  Open 200 in browser
        Open scanned host port in browser as tabs.
        Args:
            _event: not used but mandatory
        """
        port_m = Port.fetchObject(
            {"ip": self.toolmodel.ip, "port": self.toolmodel.port, "proto": self.toolmodel.proto})
        if port_m is None:
            return
        ssl = port_m.infos.get("SSL", None)
        if ssl is not None:
            url = "https://" if ssl == "True" else "http://"
            url += port_m.ip+":"+str(port_m.port)+"/"
            webbrowser.open_new_tab(url)

    def getFileOutputArg(self):
        """Returns the command line paramater giving the output file
        Returns:
            string
        """
        return " > "

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
        tags = ["todo"]
        targets = {}
        notes = file_opened.read().decode("utf-8")
        if notes == "":
            return None, None, None, None
        if not notes.startswith("- Nikto v"):
            return None, None, None, None
        host, port, service, infos = parse_nikto_plain_text(notes)
        if host:
            if port:
                ServerIp().initialize(host).addInDb()
                p_o = ServerPort().initialize(host, port, "tcp", service)
                insert_res = p_o.addInDb()
                if not insert_res["res"]:
                    p_o = ServerPort.fetchObject(pentest, {"_id": insert_res["iid"]})
                p_o.updateInfos(
                    {"Nikto": infos, "SSL": "True" if service == "https" else "False"})
                targets[str(insert_res["iid"])] = {
                    "ip": host, "port": port, "proto": "tcp"}
        return notes, tags, "port", targets
