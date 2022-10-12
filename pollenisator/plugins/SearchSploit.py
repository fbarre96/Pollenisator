"""A plugin to parse python reverse searchsploit scan"""

import re
from pollenisator.plugins.plugin import Plugin
import json

class SearchSploit(Plugin):
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
        return ".json"

    def getFileOutputPath(self, commandExecuted):
        """Returns the output file path given in the executed command using getFileOutputArg
        Args:
            commandExecuted: the command that was executed with an output file inside.
        Returns:
            string: the path to file created
        """
        ouputPath = str(commandExecuted.split(self.getFileOutputArg())[-1].strip().split(" ")[0])
        return ouputPath

    def changeCommand(self, command, outputDir, toolname):
        """
        Summary: Complete the given command with the tool output file option and filename absolute path.
        Args:
            * command : the command line to complete
            * outputDir : the directory where the output file must be generated
            * toolname : the tool name (to be included in the output file name)
        Return:
            The command complete with the tool output file option and filename absolute path.
        """
        command = super().changeCommand(command, outputDir, toolname)
        command = command.replace("\"\"", "None")
        return command

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
        notes = file_opened.read().decode("utf-8")
        try:
            jsonFile = json.loads(notes)
            if not isinstance(jsonFile, dict):
                return None, None, None, None
            if jsonFile.get("RESULTS_EXPLOIT", None) is None or jsonFile.get("RESULTS_SHELLCODE", None) is None:
                return None,None,None,None
            if jsonFile.get("SEARCH", "None") == "None":
                return "No product known detected", tags, "wave", {"wave": None}
            if len(jsonFile["RESULTS_EXPLOIT"]) == 0 :
                return notes, tags,"wave", {"wave": None}
            elif not re.match(r"\d", jsonFile["SEARCH"]):
                return notes, tags, "wave", {"wave": None}
            else:     
                tags.append("Interesting")
                for exploit in jsonFile["RESULTS_EXPLOIT"]:
                    notes += exploit["Date"] + " - " + exploit["Title"] + "\n"
                    notes += "Exploitdb path : " + exploit["Path"] + "\n"
                    notes += "\n"
                return notes, tags, "wave", {"wave": None}
        except ValueError: # Couldn't parse json file
            return notes,None,None,None

