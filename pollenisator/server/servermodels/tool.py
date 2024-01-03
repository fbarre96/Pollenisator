from pymongo import InsertOne
from pollenisator.core.components.logger_config import logger
from bson import ObjectId
from bson.errors import InvalidId
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.components.tag import Tag
from pollenisator.core.models.tool import Tool
from pollenisator.core.controllers.toolcontroller import ToolController
from pollenisator.server.servermodels.command import ServerCommand
from pollenisator.server.servermodels.element import ServerElement
from pollenisator.core.components.socketmanager import SocketManager
from pollenisator.core.components.utils import JSONEncoder, JSONDecoder
import json
from pollenisator.core.components.utils import  checkCommandService, isNetworkIp, loadPlugin, detectPluginsWithCmd
from datetime import datetime
import os
import sys
import time
from pollenisator.server.permission import permission
from pollenisator.server.token import encode_token
import socketio

class ServerTool(Tool, ServerElement):
    command_variables = ["tool.infos.*"]
    def __init__(self, pentest="", *args, **kwargs):
        dbclient = DBClient.getInstance()
        if pentest != "":
            self.pentest = pentest
        elif dbclient.current_pentest != "":
            self.pentest = dbclient.current_pentest
        else:
            raise ValueError("An empty pentest name was given and the database is not set in mongo instance.")
        super().__init__(*args, **kwargs)

    def setOutOfTime(self, pentest):
        """Set this tool as out of time (not matching any interval in wave)
        Add "OOT" in status
        """
        if "OOT" not in self.status:
            self.status.append("OOT")
            update(pentest, self._id, {"status": self.status})

    def setOutOfScope(self, pentest):
        """Set this tool as in scope (is matching at least one scope in wave)
        Remove "OOS" from status
        """
        if not "OOS" in self.status:
            self.status.append("OOS")
            update(pentest, self._id, {"status": self.status})
    
    def addInDb(self, check=True, base=None, update_check_infos=True):
        ret = do_insert(self.pentest, ToolController(self).getData(), check=check, base=base, update_check=update_check_infos)
        self._id = ret["iid"]
        return ret

    @classmethod
    def fetchObjects(cls, pentest, pipeline):
        dbclient = DBClient.getInstance()
        results = dbclient.findInDb(pentest, "tools", pipeline)
        for result in results:
            yield(cls(pentest, result))

    @classmethod
    def fetchObject(cls, pentest, pipeline):
        dbclient = DBClient.getInstance()
        result = dbclient.findInDb(pentest, "tools", pipeline, False)
        return cls(pentest, result)

    def getCommand(self):
        """
        Get the tool associated command.

        Return:
            Returns the Mongo dict command fetched instance associated with this tool's name.
        """
        dbclient = DBClient.getInstance()
        commandTemplate = dbclient.findInDb(self.pentest,
                                                 "commands", {"_id": ObjectId(self.command_iid)}, False)
        return commandTemplate
    
    def getCheckItem(self):
        from pollenisator.server.modules.cheatsheet.checkinstance import CheckInstance
        try:
            ObjectId(self.check_iid)
        except InvalidId:
           return None
        check = CheckInstance.fetchObject(self.pentest, {"_id":ObjectId(self.check_iid)})
        if check is None:
            return None
        return check.getCheckItem()

    def setInScope(self):
        """Set this tool as out of scope (not matching any scope in wave)
        Add "OOS" in status
        """
        if "OOS" in self.status:
            self.status.remove("OOS")
            update(self.pentest, self._id, ToolController(self).getData())

    def setInTime(self):
        """Set this tool as in time (matching any interval in wave)
        Remove "OOT" from status
        """
        if "OOT" in self.status:
            self.status.remove("OOT")
            update(self.pentest, self._id, ToolController(self).getData())

    def delete(self):
        """
        Delete the tool represented by this model in database.
        """
        delete(self.pentest, self._id)

    def getParentId(self):
        try:
            if self.check_iid is not None:
                return self.check_iid
            else:
                return None
        except TypeError:
            # None type returned:
            return None
        
    def findQueueIndexFromPrio(self, queue):
        priority = self.getCheckItem().priority
        i=0
        for tool_info in queue:
            queue_priority = tool_info.get("priority", 0)
            if queue_priority > priority:
                return i
            i+=1
        return i
        
    def addToQueue(self, index=None):
        dbclient = DBClient.getInstance()
        queue = dbclient.findInDb(self.pentest, "autoscan", {"type":"queue"}, False) 
        if queue is None:
            queue = list()
            dbclient.insertInDb(self.pentest, "autoscan", {"type":"queue", "tools":[]}) 
        else:
            queue = list(queue["tools"])
        if self.getId() in queue:
            return False, "Already in queue"
        priority = self.getCheckItem().priority
        if index is None:
            index=self.findQueueIndexFromPrio(queue)
            queue.insert(index, {"iid":self.getId(), "priority":priority})
        else:
            try:
                queue.insert(index, {"iid":self.getId(), "priority":priority})
            except IndexError:
                return False, "Index error"
        dbclient.updateInDb(self.pentest, "autoscan", {"type":"queue"}, {"$set":{"tools":queue}})
        return True, "Added to queue"
    
    def removeFromQueue(self):
        dbclient = DBClient.getInstance()
        dbclient.updateInDb(self.pentest, "autoscan", {"type":"queue"}, {"$pull":{"tools":{"iid":launchableToolIid}}})
        return True, "remove from to queue"
    
    @staticmethod
    def clearQueue(pentest):
        dbclient = DBClient.getInstance()
        dbclient.updateInDb(pentest, "autoscan", {"type":"queue"}, {"$set":{"tools":[]}})
        return True, "Cleared queue"
        
        
    def getCommandToExecute(self, command_o):
        """
        Get the tool bash command to execute.
        Replace the command's text's variables with tool's informations.
        Return:
            Returns the bash command of this tool instance, a marker |outputDir| is still to be replaced.
        """
        toolHasCommand = self.text
        if isinstance(command_o, str):
            command = command_o
            self.text = command
            lvl = self.lvl
        else:
            if toolHasCommand is not None and toolHasCommand.strip() != "":
                command = self.text
                lvl = self.lvl
            else:
                command = command_o.text
                lvl = self.lvl #not command lvl as it can be changed by modules
        data = self.getData()
        if self.check_iid is not None:
            from pollenisator.server.modules.cheatsheet.checkinstance import CheckInstance
            check = CheckInstance.fetchObject(self.pentest, {"_id":ObjectId(self.check_iid)})
            if check is not None:
                target = check.getTargetData()
                if target is not None:
                    infos = {**data.get("infos", {}), **target.get("infos", {})}
                    data |= target
                    data["infos"] = infos
        command = ServerElement.replaceAllCommandVariables(self.pentest, command, data)
        if isinstance(command_o, str):
            return command
        return command
    
    @classmethod
    def replaceCommandVariables(cls, pentest, command, data):
        command = cls.unpack_info(data.get("infos",{}), command, depth=0, max_depth=3)
        return command
    
    @classmethod
    def unpack_info(cls, infos_dict: dict, command: str, depth=0, max_depth=3):
        """Recursively unpack infos dict into command string
        """
        if depth > max_depth:
            return
        for key in infos_dict.keys():
            if isinstance(infos_dict[key], dict):
                command = cls.unpack_info(infos_dict[key], command, depth+1, max_depth)
            else:
                command = command.replace("|tool.infos."+str(key)+"|", str(infos_dict.get(key, '')))
        return command
    
    def getPluginName(self):
        dbclient = DBClient.getInstance()
        if self.plugin_used != "":
            return self.plugin_used
        command_o = dbclient.findInDb(self.pentest,"commands",{"_id": ObjectId(self.command_iid)}, False)
        if command_o and "plugin" in command_o.keys():
            return command_o["plugin"]
        return None

    def getPlugin(self):
        mod_name = self.getPluginName()
        if mod_name:
            mod = loadPlugin(mod_name)
            return mod
        return None

    def markAsDone(self, file_name=None):
        """Set this tool status as done but keeps OOT or OOS.
        Args:
            file_name: the resulting file of thsi tool execution. Default is None
        """
        self.datef = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
        newStatus = ["done"]
        if "OOS" in self.status:
            newStatus.append("OOS")
        if "OOT" in self.status:
            newStatus.append("OOT")
        self.status = newStatus
        self.resultfile = file_name
        dbclient = DBClient.getInstance()
        dbclient.updateInDb("pollenisator", "workers", {"name":self.scanner_ip}, {"$pull":{"running_tools": {"pentest":self.pentest, "iid":self.getId()}}})

    def markAsError(self, msg=""):
        """Set this tool status as not done by removing "done" or "running" and adding an error status.
        Also resets starting and ending date as well as worker name
        """
        self.dated = "None"
        self.datef = "None"
        dbclient = DBClient.getInstance()
        dbclient.updateInDb("pollenisator", "workers", {"name":self.scanner_ip}, {"$pull":{"running_tools": {"pentest":self.pentest, "iid":self.getId()}}})
        self.scanner_ip = "None"
        if "done" in self.status:
            self.status.remove("done")
        if "running" in self.status:
            self.status.remove("running")
        self.notes = msg
        self.status.append("error")

    def markAsTimedout(self):
        """Set this tool status as not done by removing "done" or "running" and adding an error status.
        Also resets starting and ending date as well as worker name
        """
        self.dated = "None"
        self.datef = "None"
        dbclient = DBClient.getInstance()
        dbclient.updateInDb("pollenisator", "workers", {"name":self.scanner_ip}, {"$pull":{"running_tools": {"pentest":self.pentest, "iid":self.getId()}}})
        self.scanner_ip = "None"
        if "done" in self.status:
            self.status.remove("done")
        if "running" in self.status:
            self.status.remove("running")
        self.status.append("timedout")
        
    def markAsNotDone(self):
        """Set this tool status as not done by removing "done" or "running" status.
        Also resets starting and ending date as well as worker name
        """
        self.dated = "None"
        self.datef = "None"
        dbclient = DBClient.getInstance()
        if self.scanner_ip != "None":
            dbclient.updateInDb("pollenisator", "workers", {"name":self.scanner_ip}, {"$pull":{"running_tools": {"pentest":self.pentest, "iid":self.getId()}}})
        self.scanner_ip = "None"
        if "done" in self.status:
            self.status.remove("done")
        if "running" in self.status:
            self.status.remove("running")

    def markAsRunning(self, workerName):
        """Set this tool status as running but keeps OOT or OOS.
        Sets the starting date to current time and ending date to "None"
        Args:
            workerName: the worker name that is running this tool
        """
        self.dated = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
        self.datef = "None"
        newStatus = ["running"]
        if "OOS" in self.status:
            newStatus.append("OOS")
        if "OOT" in self.status:
            newStatus.append("OOT")
        if "timedout" in self.status:
            newStatus.append("timedout")
        self.status = newStatus
        self.scanner_ip = workerName
        dbclient = DBClient.getInstance()
        dbclient.updateInDb("pollenisator", "workers", {"name":workerName}, {"$push":{"running_tools": {"pentest":self.pentest, "iid":self.getId()}}}, notify=True)

    def getDbKey(self):
        """Return a dict from model to use as unique composed key.
        Returns:
        {"wave": self.wave, "lvl": self.lvl, "check_iid":self.check_iid}
        """
        base = {"wave": self.wave, "name":self.name, "lvl": self.lvl, "check_iid":self.check_iid}
        return base
    
    def getHashableDbKey(self):
        return tuple(self.getDbKey().values())

    def __str__(self):
        """
        Get a string representation of a tool.

        Returns:
            Returns the tool name. The wave name is prepended if tool lvl is "port" or "ip"
        """
        return self.name

    def getDetailedString(self):
        """
        Get a more detailed string representation of a tool.

        Returns:
            string
        """
        if self.lvl == "import":
            return str(self.name)
        class_element = ServerElement.getClassWithTrigger(self.lvl)
        if class_element is None:
            return str(self.name)
        return class_element.completeDetailedString(self.getData()) + str(self.name)
    
    def _setStatus(self, new_status, arg):
        if "done" in new_status:
            if arg == "":
                arg = None
            self.markAsDone(arg)
        elif "running" in new_status:
            self.markAsRunning(arg)
        elif "not_done" in new_status:
            self.markAsNotDone()
        elif "ready" in new_status:
            self.markAsNotDone()
        elif "error" in new_status:
            self.markAsError(arg)
        elif "timedout" in new_status:
            self.markAsTimedout()
        elif len(new_status) == 0:
            self.markAsNotDone()
        return update(self.pentest, self.getId(), ToolController(self).getData())
    
    @classmethod
    def bulk_insert(cls, pentest, tools_to_add):
        if not tools_to_add:
            return
        dbclient = DBClient.getInstance()
        dbclient.create_index(pentest, "tools", [("wave", 1), ("name", 1), ("lvl", 1), ("check_iid", 1)])
        update_operations = []
        for tool in tools_to_add:
            data = ToolController(tool).getData()
            if "_id" in data:
                del data["_id"]
            update_operations.append(InsertOne(data))
        result = dbclient.bulk_write(pentest, "tools", update_operations)
        upserted_ids = result.upserted_ids
        return upserted_ids
    
    

    
@permission("pentester")
def setStatus(pentest, tool_iid, body):
    newStatus = body["newStatus"]
    arg = body.get("arg", "")
    tool_o = ServerTool.fetchObject(pentest, {"_id":ObjectId(tool_iid)})
    if tool_o is None:
        return "Tool not found", 404
    tool_o._setStatus(newStatus, arg)

@permission("pentester")
def delete(pentest, tool_iid):
    dbclient = DBClient.getInstance()
    if not dbclient.isUserConnected():
        return "Not connected", 503
    tool_existing = dbclient.findInDb(pentest,"tools",{"_id":ObjectId(tool_iid)}, False)
    if tool_existing is None:
        return "Not found", 404
    res = dbclient.deleteFromDb(pentest, "tools", {"_id": ObjectId(tool_iid)}, False)
    
    if tool_existing.get("check_iid") is not None and tool_existing.get("check_iid", "") != "":
        from pollenisator.server.modules.cheatsheet.checkinstance import CheckInstance
        check = CheckInstance.fetchObject(pentest, {"_id":ObjectId(tool_existing.get("check_iid"))})
        if check is not None:
            check.updateInfos()
    if res is None:
        return 0
    else:
        return res

@permission("pentester")
def insert(pentest, body, **kwargs):
    if "base" in kwargs:
        del kwargs["base"]
    do_insert(pentest, body, **kwargs)

def do_insert(pentest, body, **kwargs):
    dbclient = DBClient.getInstance()
    if not dbclient.isUserConnected():
        return "Not connected", 503
    if body.get("name", "") == "None" or body.get("name", "") == "" or body.get("name", "") is None:
        del body["name"]
    tool_o = ServerTool(pentest, body)
    # Checking unicity
    base = tool_o.getDbKey()
    if kwargs.get("base") is not None:
        for k,v in kwargs.get("base").items():
            base[k] = v 
    existing = dbclient.findInDb(pentest, "tools", base, False)
    if existing is not None:
        return {"res":False, "iid":existing["_id"]}
    if "_id" in body:
        del body["_id"]
    # Checking port /service tool
    parent = tool_o.getParentId()
    # SHould be handled in check i think
    # if tool_o.lvl == "port" and tool_o.command_iid is not None and tool_o.command_iid != "":
    #     if kwargs.get("check", True):
    #         comm = dbclient.findInDb(pentest, "commands", {"_id":ObjectId(tool_o.command_iid)}, False)
    #         port = dbclient.findInDb(pentest, "ports", {"_id":ObjectId(parent)}, False)
    #         if comm:
    #             allowed_ports_services = comm["ports"].split(",")
    #             if not checkCommandService(allowed_ports_services, port["port"], port["proto"], port["service"]):
    #                 return "This tool parent does not match its command ports/services allowed list", 403
    # Inserting tool
    base["name"] = body.get("name", "")
    base["ip"] = body.get("ip", "")
    base["scope"] = body.get("scope", "")
    base["port"] = body.get("port", "")
    base["proto"] = body.get("proto", "")
    base["command_iid"] = body.get("command_iid", "")
    base["check_iid"] = body.get("check_iid", "")
    base["scanner_ip"] = body.get("scanner_ip", "None")
    base["dated"] = body.get("dated", "None")
    base["datef"] = body.get("datef", "None")
    base["text"] = body.get("text", "")
    base["status"] = body.get("status", [])
    base["notes"] = body.get("notes", "")
    base["infos"] = body.get("infos", {})
    res_insert = dbclient.insertInDb(pentest, "tools", base, parent)
    ret = res_insert.inserted_id
    tool_o._id = ret
    if base["check_iid"] != "" and kwargs.get("update_check", True):
        from pollenisator.server.modules.cheatsheet.checkinstance import CheckInstance
        check = CheckInstance.fetchObject(pentest, {"_id":ObjectId(base["check_iid"])})
        if check is not None:
            check.updateInfos()
    # adding the appropriate tools for this scope.
    return {"res":True, "iid":ret}

@permission("pentester")
def update(pentest, tool_iid, body):
    dbclient = DBClient.getInstance()
    orig = dbclient.findInDb(pentest, "tools", {"_id":ObjectId(tool_iid)}, False)
    res = dbclient.updateInDb(pentest, "tools", {"_id":ObjectId(tool_iid)}, {"$set":body}, False, True)
    if orig.get("check_iid") is not None and orig.get("check_iid", "") != "":
        from pollenisator.server.modules.cheatsheet.checkinstance import CheckInstance
        check = CheckInstance.fetchObject(pentest, {"_id":ObjectId(orig.get("check_iid"))})
        if check is not None:
            check.updateInfos()

    return True
    
@permission("pentester")
def craftCommandLine(pentest, tool_iid, commandline_options=""):
    # CHECK TOOL EXISTS
    toolModel = ServerTool.fetchObject(pentest, {"_id": ObjectId(tool_iid)})
    if toolModel is None:
        return "Tool does not exist : "+str(tool_iid), 404
    if commandline_options != "":
        toolModel.text = commandline_options
        dbclient = DBClient.getInstance()
        dbclient.updateInDb(pentest, "tools", {"_id":ObjectId(tool_iid)}, {"$set":{"text":commandline_options}}, False, True)
    # GET COMMAND OBJECT FOR THE TOOL
    if toolModel.text == "":
        command_o = ServerCommand.fetchObject({"_id": ObjectId(toolModel.command_iid)}, pentest)
        if command_o is None:
            return "Associated command was not found", 404
    else:
        command_o = str(toolModel.text)
    # Replace vars in command text (command line)
    comm = toolModel.getCommandToExecute(command_o)
    # Read file to execute for given tool and prepend to final command
    if comm == "":
        return "An empty command line was crafted", 400
    # Load the plugin
    ext = ""
    mod = toolModel.getPlugin()
    if mod is None:
        return "Plugin not found for this tool", 400
    # craft outputfile name
    comm_complete = mod.changeCommand(comm, "|outputDir|", mod.getFileOutputExt())
    ext = mod.getFileOutputExt()
    return {"comm":comm, "ext":ext, "comm_with_output":comm_complete}

@permission("pentester")
def completeDesiredOuput(pentest, tool_iid, plugin, command_line_options):
    # CHECK TOOL EXISTS
    toolModel = ServerTool.fetchObject(pentest, {"_id": ObjectId(tool_iid)})
    if toolModel is None:
        return "Tool does not exist : "+str(tool_iid), 404
    comm = toolModel.getCommandToExecute(command_line_options)
    mod = loadPlugin(plugin)
    # craft outputfile name
    comm = mod.changeCommand(comm, "|outputDir|", "")
    return {"command_line_options":comm, "ext":mod.getFileOutputExt()}

@permission("user")
def getDesiredOutputForPlugin(body):
    cmdline = body.get("cmdline")
    plugin = body.get("plugin")
    plugin_results = {}
    if plugin == "auto-detect":
        plugins_detected = detectPluginsWithCmd(cmdline)
    else:
        plugins_detected = [plugin]
    comm = cmdline
    for plugin in plugins_detected:
        mod = loadPlugin(plugin)
        comm = mod.changeCommand(comm, f"|{plugin}.outputDir|", "")
        plugin_results[plugin] = mod.getFileOutputExt()
    return {"command_line_options":comm, "plugin_results":plugin_results}

@permission("user")
def listPlugins():
    """
    List the plugins.
    Returns:
        return the list of plugins file names.
    """
    dir_path = os.path.dirname(os.path.realpath(__file__))
    path = os.path.join(dir_path, "../../plugins/")
    # Load plugins
    sys.path.insert(0, path)
    results = []
    plugin_list = os.listdir(path)
    plugin_list = [x[:-3] for x in plugin_list if x.endswith(
        ".py") and x != "__pycache__" and x != "__init__.py" and x != "plugin.py"]
    for plugin in plugin_list:
        mod = loadPlugin(plugin)
        default_bin_names = mod.default_bin_names
        tags = [tag for tag in mod.getTags().values()]
        results.append({"plugin":plugin, "default_bin_names":default_bin_names, "tags":tags})
    return results
    
@permission("pentester")
def importResult(pentest, tool_iid, upfile, body):
    dbclient = DBClient.getInstance()
    #STORE FILE
    res, status, filepath = dbclient.do_upload(pentest, tool_iid, "result", upfile)
    if status != 200:
        return res, status
    # Analyze
    
    toolModel = ServerTool.fetchObject(pentest, {"_id": ObjectId(tool_iid)})
    if toolModel is None:
        return "Tool not found", 404
    mod = toolModel.getPlugin()
    ext = os.path.splitext(upfile.filename)[-1]
    if mod is not None:
        try:
            # Check return code by plugin (can be always true if the return code is inconsistent)
            
            notes, tags, _, _ = mod.Parse(pentest, upfile, tool=toolModel, ext=ext, filename=upfile.filename)
            if notes is None:
                notes = "No results found by plugin."
            if tags is None:
                tags = []
            if isinstance(tags, Tag):
                tags = [tags]
            # Success could be change to False by the plugin function (evaluating the return code for exemple)
            # if the success is validated, mark tool as done
            toolModel.notes = notes
            for tag in tags:
                ToolController(toolModel).addTag(tag)
            toolModel.markAsDone(filepath)
            # And update the tool in database
            update(pentest, tool_iid, ToolController(toolModel).getData())
            # Upload file to SFTP
            msg = "TASK SUCCESS : "+toolModel.name
        except IOError as e:
            toolModel.addTag(Tag("no-output", None, "error", "Failed to read results file"))
            toolModel.notes = "Failed to read results file"
            toolModel.markAsDone()
            update(pentest, tool_iid, ToolController(toolModel).getData())
    else:
        msg = "TASK FAILED (no plugin found) : "+toolModel.name
        toolModel.markAsNotDone()
        update(pentest, tool_iid, ToolController(toolModel).getData())
        raise Exception(msg)
    return "Success"


@permission("pentester")
def queueTasks(pentest, body, **kwargs):
    logger.debug("Queue tasks : "+str(body))
    results = {"successes":[], "failures":[]}
    tools_iids = set()
    commands_iids = set()
    for tool_iid in body:
        if isinstance(tool_iid, str) and tool_iid.startswith("ObjectId|"):
            tool_iid = tool_iid.replace("ObjectId|", "")
        tools_iids.add(ObjectId(tool_iid))
    tools = ServerTool.fetchObjects(pentest, {"_id": {"$in": list(tools_iids)}})
    for tool in tools:
        tool_iid = str(tool.getId())
        res, msg = tool.addToQueue()
        if res:
            results["successes"].append({"tool_iid":tool_iid})
        else:
            results["failures"].append({"tool_iid":tool_iid, "error":msg})
    return results

@permission("pentester")
def unqueueTasks(pentest, body, **kwargs):
    logger.debug("Remove tasks : "+str(body))
    results = {"successes":[], "failures":[]}
    tools_iid = body
    for tool_iid in tools_iid:
        if isinstance(tool_iid, str) and tool_iid.startswith("ObjectId|"):
            tool_iid = tool_iid.replace("ObjectId|", "")
        tool = ServerTool.fetchObject(pentest, {"_id": ObjectId(tool_iid)})
        if tool:
            res, msg = tool.removeFromQueue()
            if res:
                results["successes"].append({"tool_iid":tool_iid})
            else:
                results["failures"].append({"tool_iid":tool_iid, "error":msg})
    return results

@permission("pentester")
def clearTasks(pentest, **kwargs):
    ServerTool.clearQueue(pentest)


@permission("pentester")
def getQueue(pentest):
    dbclient = DBClient.getInstance()
    res = []
    queue = dbclient.findInDb(pentest, "autoscan", {"type":"queue"}, False)
    if queue is not None:
        tools = queue["tools"]
        tools_objects = ServerTool.fetchObjects(pentest, {"_id": {"$in": [ObjectId(tool_info.get("iid")) for tool_info in tools]}})
        commands = ServerCommand.fetchObjects({}, pentest)
        commands_dict = {str(command.getId()):command for command in commands}
        for tool in tools_objects:
            tool_data = {}
            tool_data = ToolController(tool).getData()
            if tool.text == "":
                command = commands_dict.get(str(tool.command_iid))
                if command is not None:
                    tool_data["text"] = command.get("text","")
            res.append(tool_data)
    return res

def isLaunchable(pentest, tool_iid, authorized_commands):
    logger.debug("launch task : "+str(tool_iid))
    dbclient = DBClient.getInstance()
    launchableTool = ServerTool.fetchObject(pentest, {"_id": ObjectId(tool_iid)})
    command_o = ServerCommand.fetchObject({"_id": ObjectId(launchableTool.command_iid)}, pentest)
    if authorized_commands is not None and str(command_o.getId()) not in authorized_commands:
        return "Command not authorized for autoscan", 403
    if launchableTool is None:
        logger.debug("Error in launch task : not found :"+str(tool_iid))
        return "Tool not found", 404
    if command_o is None:
        logger.debug("Error in launch task : command for tool not found :"+str(tool_iid))
        return "Command associated not found", 404
    plugin_to_run = command_o.plugin
    
    # Find a worker that can launch the tool without breaking limitations
    valid_workers = dbclient.findInDb("pollenisator", "workers", {"pentest": pentest, "supported_plugins":plugin_to_run}, True)

    logger.debug(f"Available workers are {str(valid_workers)}, (tool id {tool_iid})")
    choosenWorker = ""
    for worker in valid_workers:
        running_tools = dbclient.countInDb(pentest,"tools",{"status":"running", "scanner_ip":worker["name"]})
        if running_tools <= 5: # TODO not hardcode this parameter
            choosenWorker = worker["name"]
    if choosenWorker == "":
        logger.debug("Error in launch task : no worker available:"+str(tool_iid))
        return "No worker available", 504
    logger.debug(f"Choosen worker for tool_iid {tool_iid} is {str(choosenWorker)}")
    workerName = choosenWorker
    socket = dbclient.findInDb("pollenisator", "sockets", {"user":workerName}, False)
    if socket is None:
        logger.debug(f"Error in launching {tool_iid} : socket not found to contact {workerName}")
        return "Socket not found", 503
    return str(socket['sid']),200

def launchTask(pentest, tool_iid, socket_sid, worker_token):
    sm = SocketManager.getInstance()
    logger.debug(f"Launch task  : emit  {str(socket_sid)} toolid:{str(tool_iid)})")
    sm.socketio.emit('executeCommand', {'workerToken': worker_token, "pentest":pentest, "toolId":str(tool_iid)}, room=socket_sid)
    dbclient = DBClient.getInstance()
    dbclient.send_notify(pentest, "tools", tool_iid, "tool_start")
    return "Success", 200

@permission("pentester")
def runTask(pentest, tool_iid, **kwargs):
    msg, statuscode = isLaunchable(pentest, tool_iid, None)
    if statuscode != 200:
        return msg, statuscode
    socket_sid = msg
    encoded = encode_token(kwargs["token_info"])
    return launchTask(pentest, tool_iid, socket_sid, encoded)

@permission("pentester")
def getProgress(pentest, tool_iid):
    dbclient = DBClient.getInstance()
    tool = ServerTool.fetchObject(pentest, {"_id": ObjectId(tool_iid)})
    logger.info("Trying to get progress of task "+str(tool))
    if tool is None:
        return "Tool not found", 404
    if "done" in tool.status:
        return True
    elif "running"  not in tool.status:
        return "Tool is not running", 400
    workers = dbclient.getWorkers({})
    workerNames = [worker["name"] for worker in workers]
    saveScannerip = tool.scanner_ip
    if saveScannerip == "":
        return "Empty worker field", 400
    if saveScannerip == "localhost":
        return "Tools running in localhost cannot be stopped through API", 405
    if saveScannerip not in workerNames:
        return "The worker running this tool is not running anymore", 404
    socket = dbclient.findInDb("pollenisator", "sockets", {"user":saveScannerip}, False)
    sm = SocketManager.getInstance()
    if socket is None:
        return "Socket not found", 404
    sm.socketio.emit('getProgress', {'pentest': pentest, "tool_iid":str(tool_iid)}, room=socket["sid"])
    global response
    response = ""
    @sm.socketio.event
    def getProgressResult(data):
        global response
        response = data
        if response["result"] is None:
            response["result"] = b""
    start_time = time.time()
    while time.time() - start_time < 3:
        if len(response) == 0 or response is None:
            time.sleep(0.1)
        else:
            break
    if len(response) == 0 or response is None:
        return "Could not get worker progress", 404
    logger.info('Received response:' +str(response))
    if isinstance(response["result"], str) or  isinstance(response["result"], bool):
        return response["result"], 200
    return response["result"].decode(), 200
    
@permission("pentester")
def stopTask(pentest, tool_iid, body):
    dbclient = DBClient.getInstance()
    stopableTool = ServerTool.fetchObject(pentest, {"_id": ObjectId(tool_iid)})
    logger.info("Trying to stop task "+str(stopableTool))
    if stopableTool is None:
        return "Tool not found", 404
    workers = dbclient.getWorkers({})
    workerNames = [worker["name"] for worker in workers]
    forceReset = body["forceReset"]
    saveScannerip = stopableTool.scanner_ip
    if forceReset:
        stopableTool.markAsNotDone()
        update(pentest, tool_iid, ToolController(stopableTool).getData())
    if saveScannerip == "":
        return "Empty worker field", 400
    if saveScannerip == "localhost":
        return "Tools running in localhost cannot be stopped through API", 405
    if saveScannerip not in workerNames:
        return "The worker running this tool is not running anymore", 404
    socket = dbclient.findInDb("pollenisator", "sockets", {"user":saveScannerip}, False)
    if socket is None:
        return "The worker running this tool is not running anymore", 404
    sm = SocketManager.getInstance()
    sm.socketio.emit('stopCommand', {'pentest': pentest, "tool_iid":str(tool_iid)}, room=socket["sid"])
    if not forceReset:
        stopableTool.markAsNotDone()
        update(pentest, tool_iid, ToolController(stopableTool).getData())
    return "Success", 200

@permission("pentester")
def getDetailedString(pentest, tool_iid):
    tool = ServerTool.fetchObject(pentest, {"_id": ObjectId(tool_iid)})
    if tool is None:
        return "Tool not found", 404
    return tool.getDetailedString()

def getNbOfLaunchedCommand(pentest, worker, command_iid):
    """
    Get the total number of running commands which have the given command name

    Args:
        command_iid: The command iid to count running tools.

    Returns:
        Return the total of running tools with this command's name as an integer.
    """
    dbclient = DBClient.getInstance()
    t = dbclient.countInDb(pentest, "tools", {"command_iid": str(command_iid), "scanner_ip": worker, "dated": {
                            "$ne": "None"}, "datef": "None"})
    if t is not None:
        return t
    return 0

