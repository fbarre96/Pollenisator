"""A plugin to parse whatweb"""

import json
import re
import webbrowser
from pollenisator.core.models.ip import Ip
from pollenisator.core.models.port import Port
from pollenisator.plugins.plugin import Plugin

class WhatWeb(Plugin):
    default_bin_names = ["whatweb", "whatweb.rb"]

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
        if self.toolmodel is None:
            return
        port_m = Port.fetchObject(self.toolmodel.pentest,
            {"ip": self.toolmodel.ip, "port": self.toolmodel.port, "proto": self.toolmodel.proto})
        if port_m is None:
            return
        url = port_m.infos.get("URL", None)
        if url is not None:
            webbrowser.open_new_tab(url)

    def getFileOutputArg(self):
        """Returns the command line paramater giving the output file
        Returns:
            string
        """
        return " --log-json="

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
            return None, None, None, None
        tags = []
        targets = {}
        notes = file_opened.read().decode("utf-8", errors="ignore")
        if notes == "":
            return None, None, None, None
        try:
            data = json.loads(notes)
        except json.decoder.JSONDecodeError:
            return None, None, None, None
        regex_host = r"https?://([^\/]+)"
        oneValidWhatweb = False
        for website in data:
            keys = website.keys()
            expected_keys = ['target', 'http_status',
                             'request_config', 'plugins']
            all_keys = True
            for expected in expected_keys:
                if expected not in keys:
                    all_keys = False
                    break
            if not all_keys:
                continue
            host_port_groups = re.search(regex_host, website["target"])
            if host_port_groups is None:
                continue
            host_port = host_port_groups.group(1)
            service = "https" if "https://" in website["target"] else "http"
            if len(host_port.split(":")) == 2:
                port = host_port.split(":")[1]
                host = host_port.split(":")[0]
            else:
                host = host_port
                port = "443" if "https://" in website["target"] else "80"
            Ip(pentest).initialize(host, infos={"plugin":WhatWeb.get_name()}).addInDb()
            p_o = Port(pentest).initialize(host, port, "tcp", service, infos={"plugin":WhatWeb.get_name()})
            insert_res = p_o.addInDb()
            if not insert_res["res"]:
                p_o = Port.fetchObject(pentest, {"_id": insert_res["iid"]})
            infosToAdd = {"URL": website["target"]}
            for plugin in website.get("plugins", {}):
                item = website["plugins"][plugin].get("string")
                if isinstance(item, list):
                    if item:
                        infosToAdd[plugin] = item
                else:
                    item = str(item)
                    if item != "":
                        infosToAdd[plugin] = item
            p_o.updateInfos(infosToAdd)
            targets[str(p_o.getId())] = {
                "ip": host, "port": port, "proto": "tcp"}
            oneValidWhatweb = True
        if not oneValidWhatweb:
            return None, None, None, None
        return notes, tags, "port", targets
