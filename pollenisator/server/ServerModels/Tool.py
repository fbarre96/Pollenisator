from pollenisator.core.Components.logger_config import logger
from bson import ObjectId
from pollenisator.core.Components.mongo import MongoCalendar
from pollenisator.core.Models.Tool import Tool
from pollenisator.core.Controllers.ToolController import ToolController
from pollenisator.server.ServerModels.Command import ServerCommand
from pollenisator.server.ServerModels.Element import ServerElement
from pollenisator.core.Components.SocketManager import SocketManager

from pollenisator.core.Components.Utils import  checkCommandService, isNetworkIp, loadPlugin
from datetime import datetime
import os
import sys
import time
from pollenisator.server.permission import permission
from pollenisator.server.token import encode_token
import socketio

class ServerTool(Tool, ServerElement):

    def __init__(self, pentest="", *args, **kwargs):
        mongoInstance = MongoCalendar.getInstance()
        if pentest != "":
            self.pentest = pentest
        elif mongoInstance.calendarName != "":
            self.pentest = mongoInstance.calendarName
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
    
    def addInDb(self, check=True, base=None):
        return do_insert(self.pentest, ToolController(self).getData(), check=check, base=base)

    @classmethod
    def fetchObjects(cls, pentest, pipeline):
        mongoInstance = MongoCalendar.getInstance()
        results = mongoInstance.findInDb(pentest, "tools", pipeline)
        for result in results:
            yield(cls(pentest, result))

    @classmethod
    def fetchObject(cls, pentest, pipeline):
        mongoInstance = MongoCalendar.getInstance()
        result = mongoInstance.findInDb(pentest, "tools", pipeline, False)
        return cls(pentest, result)

    def getCommand(self):
        """
        Get the tool associated command.

        Return:
            Returns the Mongo dict command fetched instance associated with this tool's name.
        """
        mongoInstance = MongoCalendar.getInstance()
        commandTemplate = mongoInstance.findInDb(self.pentest,
                                                 "commands", {"_id": ObjectId(self.command_iid)}, False)
        return commandTemplate

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
        mongoInstance = MongoCalendar.getInstance()
        try:
            if self.lvl == "wave":
                wave = mongoInstance.findInDb(self.pentest, "waves", {"wave": self.wave}, False)
                return wave["_id"]
            elif self.lvl == "network" or self.lvl == "domain":
                return mongoInstance.findInDb(self.pentest, "scopes", {"wave": self.wave, "scope": self.scope}, False)["_id"]
            elif self.lvl == "ip":
                return mongoInstance.findInDb(self.pentest, "ips", {"ip": self.ip}, False)["_id"]
            else:
                return mongoInstance.findInDb(self.pentest, "ports", {"ip": self.ip, "port": self.port, "proto": self.proto}, False)["_id"]
        except TypeError:
            # None type returned:
            return None
        
    def getCommandToExecute(self, command_o):
        """
        Get the tool bash command to execute.
        Replace the command's text's variables with tool's informations.
        Return:
            Returns the bash command of this tool instance, a marker |outputDir| is still to be replaced.
        """
        mongoInstance = MongoCalendar.getInstance()
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
        command = command.replace("|wave|", self.wave)
        if lvl == "network" or lvl == "domain":
            command = command.replace("|scope|", self.scope)
            if isNetworkIp(self.scope) == False:
                depths = self.scope.split(".")
                if len(depths) > 2:
                    topdomain = ".".join(depths[1:])
                else:
                    topdomain = ".".join(depths)
                command = command.replace("|parent_domain|", topdomain)
        if lvl == "ip":
            command = command.replace("|ip|", self.ip)
            ip_db = mongoInstance.findInDb(self.pentest, "ips", {"ip":self.ip}, False)
            if ip_db is None:
                return ""
            ip_infos = ip_db.get("infos", {})
            for info in ip_infos:
                command = command.replace("|ip.infos."+str(info)+"|", command)
        if hasattr(self, "ip") and getattr(self, "ip", "") != "":
            command = command.replace("|ip|", self.ip)
        if hasattr(self, "port") and getattr(self, "port", "") != "":
            command = command.replace("|port|", self.port)
        if hasattr(self, "proto") and getattr(self, "proto", "") != "":
            command = command.replace("|port.proto|", self.proto)
        if hasattr(self, "port") and hasattr(self, "ip"):
            port_db = mongoInstance.findInDb(self.pentest, "ports", {"port":self.port, "proto":self.proto, "ip":self.ip}, False)
            if port_db is not None:
                command = command.replace("|port.service|", port_db.get("service", ""))
                command = command.replace("|port.product|", port_db.get("product",""))
                port_infos = port_db.get("infos", {})
                for info in port_infos:
                    command = command.replace("|port.infos."+str(info)+"|", str(port_infos[info]))
        tool_infos = self.infos
        for info in tool_infos:
            command = command.replace("|tool.infos."+str(info)+"|", str(tool_infos[info]))
        if isinstance(command_o, str):
            return command
        return command

    def getPluginName(self):
        mongoInstance = MongoCalendar.getInstance()
        if self.plugin_used != "":
            return self.plugin_used
        command_o = mongoInstance.findInDb(self.pentest,"commands",{"_id":ObjectId(self.command_iid)}, False)
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
        mongoInstance = MongoCalendar.getInstance()
        mongoInstance.updateInDb("pollenisator", "workers", {"name":self.scanner_ip}, {"$pull":{"running_tools": {"pentest":self.pentest, "iid":self.getId()}}})

    def markAsError(self):
        """Set this tool status as not done by removing "done" or "running" and adding an error status.
        Also resets starting and ending date as well as worker name
        """
        self.dated = "None"
        self.datef = "None"
        mongoInstance = MongoCalendar.getInstance()
        mongoInstance.updateInDb("pollenisator", "workers", {"name":self.scanner_ip}, {"$pull":{"running_tools": {"pentest":self.pentest, "iid":self.getId()}}})
        self.scanner_ip = "None"
        if "done" in self.status:
            self.status.remove("done")
        if "running" in self.status:
            self.status.remove("running")
        self.status.append("error")

    def markAsTimedout(self):
        """Set this tool status as not done by removing "done" or "running" and adding an error status.
        Also resets starting and ending date as well as worker name
        """
        self.dated = "None"
        self.datef = "None"
        mongoInstance = MongoCalendar.getInstance()
        mongoInstance.updateInDb("pollenisator", "workers", {"name":self.scanner_ip}, {"$pull":{"running_tools": {"pentest":self.pentest, "iid":self.getId()}}})
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
        mongoInstance = MongoCalendar.getInstance()
        if self.scanner_ip != "None":
            mongoInstance.updateInDb("pollenisator", "workers", {"name":self.scanner_ip}, {"$pull":{"running_tools": {"pentest":self.pentest, "iid":self.getId()}}})
        self.scanner_ip = "None"
        if "done" in self.status:
            self.status.remove("done")
        if "running" in self.status:
            self.status.remove("running")

    def markAsRunning(self, workerName, group_id=None, group_name=None):
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
        self.infos["group_id"] = group_id
        self.infos["group_name"] = group_name
        mongoInstance = MongoCalendar.getInstance()
        mongoInstance.updateInDb("pollenisator", "workers", {"name":workerName}, {"$push":{"running_tools": {"pentest":self.pentest, "iid":self.getId()}}}, notify=True)
    
@permission("pentester")
def setStatus(pentest, tool_iid, body):
    newStatus = body["newStatus"]
    arg = body.get("arg", "")
    tool_o = ServerTool.fetchObject(pentest, {"_id":ObjectId(tool_iid)})
    if tool_o is None:
        return "Tool not found", 404
    if "done" in newStatus:
        if arg == "":
            arg = None
        tool_o.markAsDone(arg)
    elif "running" in newStatus:
        tool_o.markAsRunning(arg)
    elif "not_done" in newStatus:
        tool_o.markAsNotDone()
    elif "ready" in newStatus:
        tool_o.markAsNotDone()
    elif "error" in newStatus:
        tool_o.markAsError()
    elif "timedout" in newStatus:
        tool_o.markAsTimedout()
    elif len(newStatus) == 0:
        tool_o.markAsNotDone()
    return update(pentest, tool_o.getId(), ToolController(tool_o).getData())

@permission("pentester")
def delete(pentest, tool_iid):
    mongoInstance = MongoCalendar.getInstance()
    if not mongoInstance.isUserConnected():
        return "Not connected", 503
    res = mongoInstance.deleteFromDb(pentest, "tools", {"_id": ObjectId(tool_iid)}, False)
    if res is None:
        return 0
    else:
        return res.deleted_count

@permission("pentester")
def insert(pentest, body, **kwargs):
    if "base" in kwargs:
        del kwargs["base"]
    do_insert(pentest, body, **kwargs)

def do_insert(pentest, body, **kwargs):
    mongoInstance = MongoCalendar.getInstance()
    if not mongoInstance.isUserConnected():
        return "Not connected", 503
    if body.get("name", "") == "None" or body.get("name", "") == "" or body.get("name", "") is None:
        del body["name"]
    tool_o = ServerTool(pentest, body)
    # Checking unicity
    base = tool_o.getDbKey()
    if kwargs.get("base") is not None:
        for k,v in kwargs.get("base").items():
            base[k] = v 
    existing = mongoInstance.findInDb(pentest, "tools", base, False)
    if existing is not None:
        return {"res":False, "iid":existing["_id"]}
    if "_id" in body:
        del body["_id"]
    # Checking port /service tool
    parent = tool_o.getParentId()
    if tool_o.lvl == "port" and tool_o.command_iid is not None and tool_o.command_iid != "":
        if kwargs.get("check", True):
            comm = mongoInstance.findInDb(pentest, "commands", {"_id":ObjectId(tool_o.command_iid)}, False)
            port = mongoInstance.findInDb(pentest, "ports", {"_id":ObjectId(parent)}, False)
            if comm:
                allowed_ports_services = comm["ports"].split(",")
                if not checkCommandService(allowed_ports_services, port["port"], port["proto"], port["service"]):
                    return "This tool parent does not match its command ports/services allowed list", 403
    # Inserting tool
    base["command_iid"] = body.get("command_iid", "")
    base["scanner_ip"] = body.get("scanner_ip", "None")
    base["dated"] = body.get("dated", "None")
    base["datef"] = body.get("datef", "None")
    base["text"] = body.get("text", "")
    base["status"] = body.get("status", [])
    base["notes"] = body.get("notes", "")
    base["tags"] = body.get("tags", [])
    base["infos"] = body.get("infos", {})
    res_insert = mongoInstance.insertInDb(pentest, "tools", base, parent)
    ret = res_insert.inserted_id
    tool_o._id = ret
    # adding the appropriate tools for this scope.
    return {"res":True, "iid":ret}

@permission("pentester")
def update(pentest, tool_iid, body):
    mongoInstance = MongoCalendar.getInstance()
    tags = body.get("tags", [])
    for tag in tags:
        mongoInstance.doRegisterTag(pentest, tag)
    res = mongoInstance.updateInDb(pentest, "tools", {"_id":ObjectId(tool_iid)}, {"$set":body}, False, True)
    return True
    
@permission("pentester")
def craftCommandLine(pentest, tool_iid):
    # CHECK TOOL EXISTS
    toolModel = ServerTool.fetchObject(pentest, {"_id": ObjectId(tool_iid)})
    if toolModel is None:
        return "Tool does not exist : "+str(tool_iid), 404
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
    
    mod = toolModel.getPlugin()
    if mod is None:
        return "Plugin not found for this tool", 400
    # craft outputfile name
    comm = mod.changeCommand(comm, "|outputDir|", mod.getFileOutputExt())
    return {"comm":comm, "ext":mod.getFileOutputExt()}

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
    mod = loadPlugin(plugin)
    comm = mod.changeCommand(cmdline, "|outputDir|", "")
    return {"command_line_options":comm, "ext":mod.getFileOutputExt()}

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
    plugin_list = os.listdir(path)
    plugin_list = [x[:-3] for x in plugin_list if x.endswith(
        ".py") and x != "__pycache__" and x != "__init__.py" and x != "plugin.py"]
    return plugin_list
    
@permission("pentester")
def importResult(pentest, tool_iid, upfile, body):
    mongoInstance = MongoCalendar.getInstance()
    #STORE FILE
    res, status, filepath = mongoInstance.do_upload(pentest, tool_iid, "result", upfile)
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
            if isinstance(tags, str):
                tags = [tags]
            # Success could be change to False by the plugin function (evaluating the return code for exemple)
            # if the success is validated, mark tool as done
            toolModel.notes = notes
            for tag in tags:
                toolModel.addTag(tag)
            toolModel.markAsDone(filepath)
            # And update the tool in database
            update(pentest, tool_iid, ToolController(toolModel).getData())
            # Upload file to SFTP
            msg = "TASK SUCCESS : "+toolModel.name
        except IOError as e:
            toolModel.addTag("no-output")
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
def launchTask(pentest, tool_iid, body, **kwargs):
    logger.debug("launch task : "+str(tool_iid))
    worker_token = kwargs.get("worker_token") if kwargs.get("worker_token") else encode_token(kwargs.get("token_info"))
    mongoInstance = MongoCalendar.getInstance()
    launchableTool = ServerTool.fetchObject(pentest, {"_id": ObjectId(tool_iid)})
    command_o = ServerCommand.fetchObject({"_id": ObjectId(launchableTool.command_iid)}, pentest)
    if launchableTool is None:
        logger.debug("Error in launch task : not found :"+str(tool_iid))
        return "Tool not found", 404
    if command_o is None:
        logger.debug("Error in launch task : command for tool not found :"+str(tool_iid))
        return "Command associated not found", 404
    
    # Find a worker that can launch the tool without breaking limitations
    workers = [x["name"] for x in mongoInstance.getWorkers({"pentest":pentest})]
    logger.debug(f"Available workers are {str(workers)}, (tool id {tool_iid})")
    choosenWorker = ""
    for owner in command_o.owners:
        if owner in workers:
            choosenWorker = owner
    if choosenWorker == "":
        logger.debug("Error in launch task : no worker available:"+str(tool_iid))
        return "No worker available", 404
    logger.debug(f"Choosen worker for tool_iid {tool_iid} is {str(choosenWorker)}")
    workerName = choosenWorker
    socket = mongoInstance.findInDb("pollenisator", "sockets", {"user":workerName}, False)
    if socket is None:
        logger.debug(f"Error in launching {tool_iid} : socket not found to contact {workerName}")
        return "Socket not found", 503
    launchableToolId = launchableTool.getId()
    # launchableTool.markAsRunning(workerName, body.get("group_id"), body.get("group_name"))
    # logger.debug(f"Mark as running tool_iid {tool_iid}")
    # update(pentest, tool_iid, ToolController(launchableTool).getData())
    # Mark the tool as running (scanner_ip is set and dated is set, datef is "None")
    # Use socket sid as room so that only this worker will receive this task
    
    sm = SocketManager.getInstance()
    logger.debug(f"Launch task to worker {workerName} : emit  {str(socket['sid'])} toolid:{str(launchableToolId)})")
    sm.socketio.emit('executeCommand', {'workerToken': worker_token, "pentest":pentest, "toolId":str(launchableToolId), "infos":{"group_id":str(body.get("group_id")), "group_name":body.get("group_name")}}, room=socket["sid"])
    
    return "Success ", 200

@permission("pentester")
def getProgress(pentest, tool_iid):
    mongoInstance = MongoCalendar.getInstance()
    tool = ServerTool.fetchObject(pentest, {"_id": ObjectId(tool_iid)})
    logger.info("Trying to get progress of task "+str(tool))
    if tool is None:
        return "Tool not found", 404
    if "done" in tool.status:
        return True
    elif "running"  not in tool.status:
        return "Tool is not running", 400
    workers = mongoInstance.getWorkers({})
    workerNames = [worker["name"] for worker in workers]
    saveScannerip = tool.scanner_ip
    if saveScannerip == "":
        return "Empty worker field", 400
    if saveScannerip == "localhost":
        return "Tools running in localhost cannot be stopped through API", 405
    if saveScannerip not in workerNames:
        return "The worker running this tool is not running anymore", 404
    socket = mongoInstance.findInDb("pollenisator", "sockets", {"user":saveScannerip}, False)
    sm = SocketManager.getInstance()
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
    if isinstance(response["result"], str):
        return response["result"], 200
    return response["result"].decode(), 200
    
@permission("pentester")
def stopTask(pentest, tool_iid, body):
    mongoInstance = MongoCalendar.getInstance()
    stopableTool = ServerTool.fetchObject(pentest, {"_id": ObjectId(tool_iid)})
    logger.info("Trying to stop task "+str(stopableTool))
    if stopableTool is None:
        return "Tool not found", 404
    workers = mongoInstance.getWorkers({})
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
    socket = mongoInstance.findInDb("pollenisator", "sockets", {"user":saveScannerip}, False)
    if socket is None:
        return "The worker running this tool is not running anymore", 404
    sm = SocketManager.getInstance()
    sm.socketio.emit('stopCommand', {'pentest': pentest, "tool_iid":str(tool_iid)}, room=socket["sid"])
    if not forceReset:
        stopableTool.markAsNotDone()
        update(pentest, tool_iid, ToolController(stopableTool).getData())
    return "Success", 200


def getNbOfLaunchedCommand(calendarName, worker, command_iid):
    """
    Get the total number of running commands which have the given command name

    Args:
        command_iid: The command iid to count running tools.

    Returns:
        Return the total of running tools with this command's name as an integer.
    """
    mongoInstance = MongoCalendar.getInstance()
    t = mongoInstance.countInDb(calendarName, "tools", {"command_iid": str(command_iid), "scanner_ip": worker, "dated": {
                            "$ne": "None"}, "datef": "None"})
    if t is not None:
        return t
    return 0

