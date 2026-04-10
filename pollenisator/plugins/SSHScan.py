"""A plugin to parse sshscan"""

import json
from pollenisator.core.components.tag import Tag
from pollenisator.core.models.ip import Ip
from pollenisator.core.models.port import Port
from pollenisator.plugins.plugin import Plugin
from pollenisator.plugins.plugin_result import PluginResult, InfoUpdate, TagAddition

class SSHScan(Plugin):
    default_bin_names = ["ssh-scan", "ssh_scan"]

    def getFileOutputArg(self):
        """Returns the command line paramater giving the output file
        Returns:
            string
        """
        return " -o "

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
        return commandExecuted.split(self.getFileOutputArg())[-1].strip().split(" ")[0]

    def getTags(self):
        """Returns a list of tags that can be added by this plugin
        Returns:
            list of strings
        """
        return {"info-sshscan": Tag("info-sshscan"), 
                "pwned-ssh-nopassword": Tag("pwned-ssh-nopassword", level="high", color="red"),
                "SSH-flaw": Tag("SSH-flaw", level="low", color="yellow")}

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
        if kwargs.get("ext", "").lower() != self.getFileOutputExt():
            return PluginResult.empty()
        notes = ""
        tags = [self.getTags()["info-sshscan"]]
        content = file_opened.read().decode("utf-8", errors="ignore")
        targets = {}
        try:
            notes_json = json.loads(content)
        except json.decoder.JSONDecodeError:
            return PluginResult.empty()
        oneScanIsValid = False
        result = PluginResult(notes=notes, tags=tags, lvl="port", targets=targets)
        for scan in notes_json:
            try:
                if scan.get('ssh_scan_version', None) is None:
                    continue
                ips = [scan["hostname"], scan["ip"]]
                port = str(scan["port"])
                for ip in ips:
                    if ip.strip() == "":
                        continue
                    result.ips.append(Ip(pentest).initialize(ip, infos={"plugin": SSHScan.get_name()}))
                    result.ports.append(Port(pentest).initialize(ip, port, "tcp", "ssh", infos={"plugin": SSHScan.get_name()}))
                    port_key = {"ip": ip, "port": port, "proto": "tcp"}
                    scan_notes = "\n".join(
                        scan["compliance"].get("recommendations", []))
                    targets["sshscan_" + ip + "_" + port] = {
                        "ip": ip, "port": port, "proto": "tcp"}
                    oneScanIsValid = True
                    if "nopassword" in scan["auth_methods"]:
                        result.tags = [self.getTags()["pwned-ssh-nopassword"]]
                    # Will not exit if port was not ssh
                    is_ok = scan["compliance"]["compliant"]
                    if str(is_ok) == "False":
                        result.info_updates.append(InfoUpdate(
                            collection="ports",
                            db_key=port_key,
                            infos={"compliant": "False"}
                        ))
                        result.info_updates.append(InfoUpdate(
                            collection="ports",
                            db_key=port_key,
                            infos={"auth_methods": scan["auth_methods"]}
                        ))
                        result.tag_additions.append(TagAddition(
                            collection="ports",
                            db_key=port_key,
                            tag=Tag(self.getTags()["SSH-flaw"], notes=scan_notes)
                        ))
                    notes = scan_notes
            except KeyError:
                continue
        if not oneScanIsValid:
            return PluginResult.empty()
        result.notes = notes
        return result
