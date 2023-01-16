"""A plugin to parse gowitness"""

import json
import re
import webbrowser
from pollenisator.plugins.plugin import Plugin
from pollenisator.server.ServerModels.Ip import ServerIp
from pollenisator.server.ServerModels.Port import ServerPort

class Gowitness(Plugin):
    autoDetect = False
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
        port_m = ServerPort.fetchObject(
            {"ip": self.toolmodel.ip, "port": self.toolmodel.port, "proto": self.toolmodel.proto})
        if port_m is None:
            return
        url = port_m.infos.get("URL", None)
        if url is not None:
            webbrowser.open_new_tab(url)

    def changeCommand(self, command, outputDir, toolname):
        """
        Summary: Complete the given command with the tool output file option and filename absolute path.
        Args:
            * command : the command line to complete
            * outputDir : the directory where the output file must be generated
            * toolname : the tool name (to be included in the output file name)
        Return:
            The command completed with the tool output file option and filename absolute path.
        """
        # zip all
        return f"{command} --db-path {outputDir}.sqlite3 --screenshot-path {outputDir} && zip" + self.getFileOutputArg()+outputDir+toolname+ f" {outputDir}.sqlite3 {outputDir}"

    def getFileOutputArg(self):
        """Returns the command line paramater giving the output file
        Returns:
            string
        """
        return " -rj "

    def getFileOutputExt(self):
        """Returns the expected file extension for this command result file
        Returns:
            string
        """
        return ".zip"

    def getFileOutputPath(self, commandExecuted):
        """Returns the output file path given in the executed command using getFileOutputArg
        Args:
            commandExecuted: the command that was executed with an output file inside.
        Returns:
            string: the path to file created
        """
        return commandExecuted.split(self.getFileOutputArg())[-1].strip().split(" ")[0]


    def Parse(self, pentest, file_opened, **kwargs):
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
        if kwargs.get("ext", "").lower() != self.getFileOutputExt():
            return None, None, None, None
        tags = []
        targets = {}
        notes = file_opened.read(2).decode("utf-8")
        if notes != "PK":
            return None, None, None, None
        notes = "Valid zip received. Extract them using a script."
        return notes, tags, "port", targets
