from bson import ObjectId
from core.Components.mongo import MongoCalendar
from core.Models.Tool import Tool
from core.Controllers.ToolController import ToolController
from server.ServerModels.Command import ServerCommand
from server.ServerModels.CommandGroup import ServerCommandGroup
from server.ServerModels.Element import ServerElement
from server.FileManager import _upload
from core.Components.Utils import JSONEncoder, fitNowTime, loadToolsConfig, isNetworkIp, loadPlugin, loadPluginByBin
import json
import time
from datetime import datetime
import io

mongoInstance = MongoCalendar.getInstance()

class ServerTool(Tool, ServerElement):

    def __init__(self, pentest="", *args, **kwargs):
        super().__init__(*args, **kwargs)
        if pentest != "":
            self.pentest = pentest
        elif mongoInstance.calendarName != "":
            self.pentest = mongoInstance.calendarName
        else:
            raise ValueError("An empty pentest name was given and the database is not set in mongo instance.")
        mongoInstance.connectToDb(self.pentest)

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
    
    def addInDb(self):
        return insert(self.pentest, ToolController(self).getData())

    @classmethod
    def fetchObjects(cls, pentest, pipeline):
        mongoInstance.connectToDb(pentest)
        results = mongoInstance.find("tools", pipeline)
        for result in results:
            yield(cls(pentest, result))

    @classmethod
    def fetchObject(cls, pentest, pipeline):
        mongoInstance.connectToDb(pentest)
        result = mongoInstance.find("tools", pipeline, False)
        return cls(pentest, result)

    def getCommand(self):
        """
        Get the tool associated command.

        Return:
            Returns the Mongo dict command fetched instance associated with this tool's name.
        """
        
        commandTemplate = mongoInstance.findInDb(self.pentest,
                                                 "commands", {"name": self.name}, False)
        return commandTemplate

    def setInScope(self):
        """Set this tool as out of scope (not matching any scope in wave)
        Add "OOS" in status
        """
        if "OOS" in self.status:
            self.status.remove("OOS")
            update(pentest, self._id, ToolController(self).getData())

    def setInTime(self):
        """Set this tool as in time (matching any interval in wave)
        Remove "OOT" from status
        """
        if "OOT" in self.status:
            self.status.remove("OOT")
            update(pentest, self._id, ToolController(self).getData())

    def delete(self):
        """
        Delete the tool represented by this model in database.
        """
        delete(self.pentest, self._id)

    def getParentId(self):
        mongoInstance.connectToDb(self.pentest)
        try:
            if self.lvl == "wave":
                wave = mongoInstance.find("waves", {"wave": self.wave}, False)
                return wave["_id"]
            elif self.lvl == "network" or self.lvl == "domain":
                return mongoInstance.find("scopes", {"wave": self.wave, "scope": self.scope}, False)["_id"]
            elif self.lvl == "ip":
                return mongoInstance.find("ips", {"ip": self.ip}, False)["_id"]
            else:
                return mongoInstance.find("ports", {"ip": self.ip, "port": self.port, "proto": self.proto}, False)["_id"]
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
        toolHasCommand = self.text
        if toolHasCommand is not None and toolHasCommand.strip() != "":
            command = self.text
            lvl = self.lvl
        else:
            command = command_o.text
            lvl = command_o.lvl
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
            ip_db = mongoInstance.find("ips", {"ip":self.ip}, False)
            ip_infos = ip_db.get("infos", {})
            for info in ip_infos:
                command = command.replace("|ip.infos."+str(info)+"|", command)
        if lvl == "port":
            command = command.replace("|ip|", self.ip)
            command = command.replace("|port|", self.port)
            command = command.replace("|port.proto|", self.proto)
            port_db = mongoInstance.find("ports", {"port":self.port, "proto":self.proto, "ip":self.ip}, False)
            command = command.replace("|port.service|", port_db["service"])
            command = command.replace("|port.product|", port_db["product"])
            port_infos = port_db.get("infos", {})
            for info in port_infos:
                # print("replacing "+"|port.infos."+str(info)+"|"+ "by "+str(info))
                command = command.replace("|port.infos."+str(info)+"|", str(port_infos[info]))
        return command

    def getPlugin(self, pluginSuggestion, toolConfig):
        if pluginSuggestion.strip() == "":
            mod = loadPlugin(toolConfig["plugin"])
        elif pluginSuggestion.strip() == "auto-detect":
            mod = loadPluginByBin(self.name.split("::")[0])
        else:
            mod = loadPlugin(pluginSuggestion)
        return mod

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

    def markAsError(self):
        """Set this tool status as not done by removing "done" or "running" and adding an error status.
        Also resets starting and ending date as well as worker name
        """
        self.dated = "None"
        self.datef = "None"
        self.scanner_ip = "None"
        if "done" in self.status:
            self.status.remove("done")
        if "running" in self.status:
            self.status.remove("running")
        self.status.append("error")
        
    def markAsNotDone(self):
        """Set this tool status as not done by removing "done" or "running" status.
        Also resets starting and ending date as well as worker name
        """
        self.dated = "None"
        self.datef = "None"
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
        self.status = newStatus
        self.scanner_ip = workerName

def delete(pentest, tool_iid):
    mongoInstance.connectToDb(pentest)
    if not mongoInstance.isUserConnected():
        return "Not connected", 503
    res = mongoInstance.delete("tools", {"_id": ObjectId(tool_iid)}, False)
    if res is None:
        return 0
    else:
        return res.deleted_count

def insert(pentest, data):
    mongoInstance.connectToDb(pentest)
    if not mongoInstance.isUserConnected():
        return "Not connected", 503
    tool_o = ServerTool(pentest, data)
    # Checking unicity
    base = tool_o.getDbKey()
    existing = mongoInstance.find("tools", base, False)
    if existing is not None:
        return {"res":False, "iid":existing["_id"]}
    if "_id" in data:
        del data["_id"]
    # Inserting scope
    parent = tool_o.getParentId()
    base["scanner_ip"] = data.get("scanner_ip", "None")
    base["dated"] = data.get("dated", "None")
    base["datef"] = data.get("datef", "None")
    res_insert = mongoInstance.insert("tools", base, parent)
    ret = res_insert.inserted_id
    tool_o._id = ret
    # adding the appropriate tools for this scope.
    return {"res":True, "iid":ret}


def update(pentest, tool_iid, data):
    mongoInstance.connectToDb(pentest)
    res = mongoInstance.update("tools", {"_id":ObjectId(tool_iid)}, {"$set":data}, False, True)
    return res

def craftCommandLine(pentest, tool_iid, plugin):
    # CHECK TOOL EXISTS
    toolModel = ServerTool.fetchObject(pentest, {"_id": ObjectId(tool_iid)})
    if toolModel is None:
        return "Tool does not exist : "+str(tool_iid), 404
    # GET COMMAND OBJECT FOR THE TOOL
    command_o = ServerCommand.fetchObject({"name": toolModel.name}, pentest)
    
    # Replace vars in command text (command line)
    comm = toolModel.getCommandToExecute(command_o)
    # Load tool config
    tools_infos = loadToolsConfig()
    if plugin.strip() == "":
        if toolModel.name not in list(tools_infos.keys()):
            return "This tool has no plugin configured and no plugin was specified", 400
    # Read file to execute for given tool and prepend to final command
    if tools_infos.get(toolModel.name, None) is None:
        bin_path = ""
    else:
        bin_path = tools_infos[toolModel.name].get("bin")
        if bin_path is not None:
            if not bin_path.endswith(" "):
                bin_path = bin_path+" "
    comm = bin_path+comm
    if comm == "":
        return "An empty command line was crafted", 400
    # Load the plugin
    mod = toolModel.getPlugin(plugin, tools_infos[toolModel.name])
      
    # craft outputfile name
    
    comm = mod.changeCommand(comm, "|outputDir|", mod.getFileOutputExt())
    return {"comm":comm, "ext":mod.getFileOutputExt()}
    
def importResult(pentest, tool_iid, upfile, plugin, returncode):
    #STORE FILE
    res, status, filepath = _upload(pentest, tool_iid, "result", upfile)
    if status != 200:
        return res, status
    # Analyze
    upfile.stream.seek(0)
    mongoInstance.connectToDb(pentest)
    toolModel = ServerTool.fetchObject(pentest, {"_id": ObjectId(tool_iid)})
    if toolModel is None:
        return "Tool not found", 404
    tools_infos = loadToolsConfig()
    if plugin.strip() == "":
        if toolModel.name not in list(tools_infos.keys()):
            return "This tool has no plugin configured and no plugin was specified", 400
    mod = toolModel.getPlugin(plugin, tools_infos[toolModel.name])
    if mod is not None:
        try:
            # Check return code by plugin (can be always true if the return code is inconsistent)
            if mod.checkReturnCode(returncode):
                notes, tags, _, _ = mod.Parse(pentest, upfile)
                if notes is None:
                    notes = "No results found by plugin."
                if tags is None:
                    tags = []
                if isinstance(tags, str):
                    tags = [tags]
                # Success could be change to False by the plugin function (evaluating the return code for exemple)
                # if the success is validated, mark tool as done
                toolModel.notes = notes
                toolModel.tags = tags
                toolModel.markAsDone(filepath)
                # And update the tool in database
                update(pentest, tool_iid, ToolController(toolModel).getData())
                # Upload file to SFTP
                msg = "TASK SUCCESS : "+toolModel.name
            else:  # BAS RESULT OF PLUGIN
                msg = "TASK FAILED (says the mod) : "+toolModel.name
                msg += "The return code was not the expected one. ("+str(
                    returncode)+")."
                toolModel.markAsError()
                update(pentest, tool_iid, ToolController(toolModel).getData())
                raise Exception(msg)
        except IOError as e:
            toolModel.tags = ["todo"]
            toolModel.notes = "Failed to read results file"
            toolModel.markAsDone()
            update(pentest, tool_iid, ToolController(toolModel).getData())
    else:
        msg = "TASK FAILED (no plugin found) : "+toolModel.name
        toolModel.markAsNotDone()
        update(pentest, tool_iid, ToolController(toolModel).getData())
        raise Exception(msg)
    return "Success"

def launchTask(pentest, tool_iid, data):
    mongoInstance.connectToDb(pentest)
    launchableTool = ServerTool.fetchObject(pentest, {"_id": ObjectId(tool_iid)})
    if launchableTool is None:
        return "Tool not found", 404
    checks = data["checks"]
    plugin = data["plugin"]
    # Find a worker that can launch the tool without breaking limitations
    workers = mongoInstance.getWorkers({"excludedDatabases":{"$nin":[pentest]}})
    choosenWorker = ""
    for worker in workers:
        workerName = worker["name"]
        if hasRegistered(workerName, launchableTool):
            if checks == False:
                choosenWorker = workerName
            elif hasSpaceFor(workerName, launchableTool, pentest):
                choosenWorker = workerName
                break
    if choosenWorker == "":
        return "No worker available", 404
    workerName = choosenWorker
    launchableToolId = launchableTool.getId()
    print("Mark as running tool "+str(launchableTool))
    launchableTool.markAsRunning(workerName)
    update(pentest, tool_iid, ToolController(launchableTool).getData())
    # Mark the tool as running (scanner_ip is set and dated is set, datef is "None")
    # Add a queue to the selected worker for this tool, So that only this worker will receive this task
    instructions = mongoInstance.insertInDb("pollenisator", "instructions", {"worker":workerName, "date":datetime.now(), "function":"executeCommand",
                                                                             "args":[pentest, str(launchableToolId), plugin]})
    return instructions.inserted_id, 200

def stopTask(pentest, tool_iid, data):
    mongoInstance.connectToDb(pentest)
    stopableTool = ServerTool.fetchObject(pentest, {"_id": ObjectId(tool_iid)})
    if stopableTool is None:
        return "Tool not found", 404
    workers = mongoInstance.getWorkers({})
    workerNames = [worker["name"] for worker in workers]
    forceReset = data["forceReset"]
    saveScannerip = stopableTool.scanner_ip
    if forceReset:
        stopableTool.markAsNotDone()
        print("mark as not done")
        update(pentest, tool_iid, ToolController(stopableTool).getData())
    if saveScannerip == "":
        return "Empty worker field", 400
    if saveScannerip == "localhost":
        return "Tools running in localhost cannot be stopped through API", 405
    if saveScannerip not in workerNames:
        return "The worker running this tool is no more running", 404
    instructions = mongoInstance.insertInDb("pollenisator", "instructions", {"worker":saveScannerip, "date":datetime.now(), "function":"stopCommand",
                                                                             "args":[pentest, str(tool_iid)]})
    if not forceReset:
        stopableTool.markAsNotDone()
        update(pentest, tool_iid, ToolController(stopableTool).getData())
    return True

def hasRegistered(worker, launchableTool):
    """
    Returns a bool indicating if the worker has registered a given tool
    Args:
        launchableTool: the tool object to check registration of.
    Returns:
        Return bool.
    """
    list_registered_command = mongoInstance.getRegisteredCommands(worker)
    if list_registered_command is None:
        return False
    return (launchableTool.name in list_registered_command)

def hasSpaceFor(worker, launchableTool, calendarName):
    """
    Check if this worker has space for the given tool. (this checks the command and every group of commands max_thred settings)

    Args:
        launchableTool: a tool documents fetched from database that has to be launched

    Returns:
        Return True if a command of the tool's type can be launched on this worker, False otherwise.
    """

    # 1. Find command with command id
    command = ServerCommand.fetchObject({"name": launchableTool.name}, calendarName)
    if command.safe == "False":
        return False
    # 2. Calculate individual command limit for the server
    nb = getNbOfLaunchedCommand(worker, command.name) + 1
    
    if nb > int(command.max_thread):
        #print("Can't launch "+command.name+" on worker cause command max_trhad "+str(nb)+" > "+str(int(command.max_thread)))
        return False
    # 3. Get groups of command incorporation command id
    command_groups = ServerCommandGroup.fetchObjects(
        {"commands": {"$elemMatch": {"$eq": command.name}}})
    # 4. Calculate limites for the group
    for group in command_groups:
        tots = 0
        for commandName in group.commands:
            tots += getNbOfLaunchedCommand(worker, commandName)
        if tots + 1 > int(group.max_thread):
            #print("Can't launch "+command.name+" on worker cause group_max_thread "+str(tots + 1)+" > "+str(int(group.max_thread)))
            return False
    return True

def getNbOfLaunchedCommand(worker, commandName):
    """
    Get the total number of running commands which have the given command name

    Args:
        commandName: The command name to count running tools.

    Returns:
        Return the total of running tools with this command's name as an integer.
    """
    t = mongoInstance.findInDb("tools", {"name": commandName, "scanner_ip": worker, "dated": {
                            "$ne": "None"}, "datef": {"$eq": "None"}})
    if t is not None:
        return t.count()
    return 0