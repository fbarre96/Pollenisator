"""A plugin to parse a bluekeep scan : rdpscan"""
from core.plugins.plugin import Plugin
from server.ServerModels.Ip import ServerIp
from server.ServerModels.Port import ServerPort
from server.ServerModels.Defect import ServerDefect


class BlueKeep(Plugin):
    """Inherits Plugin
    A plugin to parse a bluekeep scan : rdpscan"""

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


    def Parse(self, pentest, file_opened, **kwargs):
        """
        Parse a opened file to extract information
        Example file:
        10.0.0.1 - UNKNOWN - no connection - timeout
        10.0.0.2 - VULNERABLE - ?? - ????

        Args:
            file_opened: the open file
            kwargs: port("") and proto("") are valid
        Returns:
            a tuple with 4 values (All set to None if Parsing wrong file): 
                0. notes: notes to be inserted in tool giving direct info to pentester
                1. tags: a list of tags to be added to tool 
                2. lvl: the level of the command executed to assign to given targets
                3. targets: a list of composed keys allowing retrieve/insert from/into database targerted objects.
        """
        # 5. Parse the file has you want.
        # Here add a note to the tool's notes of each warnings issued by this testssl run.
        notes = ""
        tags = ["Neutral"]
        targets = {}
        for line in file_opened:
            # Auto Detect
            line = line.decode("utf-8")
            infos = line.split(" - ")
            if len(infos) < 3:
                return None, None, None, None
            if not ServerIp.isIp(infos[0]):
                return None, None, None, None
            if infos[1] not in ["UNKNOWN", "SAFE", "VULNERABLE"]:
                return None, None, None, None
            # Parse
            ip = line.split(" ")[0].strip()
            ServerIp().initialize(ip).addInDb()
            p_o = ServerPort.fetchObject(pentest, {"ip": ip, "port": kwargs.get(
                "port", None), "proto": kwargs.get("proto", None)})
            if p_o is not None:
                targets[str(p_o.getId())] = {"ip": ip, "port": kwargs.get(
                    "port", None), "proto": kwargs.get("proto", None)}
            if "VULNERABLE" in line:
                ServerDefect().initialize(ip, kwargs.get("port", None), kwargs.get("proto", None), "Serveur vulnérable à BlueKeep",
                                    "Difficile", "Critique", "Critique", "N/A", ["Socle"], notes=notes, proofs=[]).addInDb()
                tags=["P0wned!"]
                if p_o is not None:
                    p_o.addTag("P0wned!")
                ip_o = ServerIp.fetchObject(pentest, {"ip": ip})
                if ip_o is not None:
                    ip_o.addTag("P0wned!")
            elif "UNKNOWN" in line:
                tags = ["todo"]
            notes += line
        return notes, tags, "port", targets
