"""A plugin to parse a bluekeep scan : rdpscan"""
from pollenisator.core.models.ip import Ip
from pollenisator.core.models.port import Port
from pollenisator.plugins.plugin import Plugin
from pollenisator.core.components.tag import Tag
from pollenisator.plugins.plugin_result import PluginResult, TagAddition

class BlueKeep(Plugin):
    """Inherits Plugin
    A plugin to parse a bluekeep scan : rdpscan"""
    default_bin_names = ["bluekeep", "rdpscan"]

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
        return {"pwned-bluekeep" : Tag("pwned-bluekeep", "red", "high"),"todo-bluekeep": Tag("todo-bluekeep", None, "todo")}

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
        tags = ["neutral"]
        targets = {}
        success = False
        result = PluginResult(lvl="port")
        for line in file_opened:
            # Auto Detect
            try:
                line = line.decode("utf-8", errors="ignore")
            except UnicodeDecodeError:
                return PluginResult.empty()
            infos = line.split(" - ")
            if len(infos) < 3:
                return PluginResult.empty()
            if not Ip.isIp(infos[0]):
                return PluginResult.empty()
            if infos[1] not in ["UNKNOWN", "SAFE", "VULNERABLE"]:
                return PluginResult.empty()
            # Parse
            ip = line.split(" ")[0].strip()
            success = True
            result.ips.append(Ip(pentest).initialize(ip, infos={"plugin":BlueKeep.get_name()}))
            if kwargs.get("port", None) is not None and kwargs.get("proto", None) is not None:
                targets[ip] = {"ip": ip, "port": kwargs.get(
                    "port", None), "proto": kwargs.get("proto", None)}
            if "VULNERABLE" in line:
                vuln_tag = Tag(self.getTags()["pwned-bluekeep"], notes=line)
                result.tag_additions.append(TagAddition(
                    collection="ips",
                    db_key={"ip": ip},
                    tag=vuln_tag
                ))
                if kwargs.get("port", None) is not None and kwargs.get("proto", None) is not None:
                    result.tag_additions.append(TagAddition(
                        collection="ports",
                        db_key={"ip": ip, "port": kwargs.get("port", None), "proto": kwargs.get("proto", None)},
                        tag=vuln_tag
                    ))
            elif "UNKNOWN" in line:
                tags = [self.getTags()["todo-bluekeep"]]
            notes += line
        if not success:
            return PluginResult.empty()
        result.notes = notes
        result.tags = tags
        result.targets = targets
        return result
