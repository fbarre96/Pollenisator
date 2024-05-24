"""
Handle request common to Tools
"""
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple, Union, cast
from typing_extensions import TypedDict
from bson import ObjectId
from bson.errors import InvalidId
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.components.tag import Tag
from pollenisator.core.components.socketmanager import SocketManager
from pollenisator.core.models.command import Command
from pollenisator.core.components.utils import loadPlugin, detectPluginsWithCmd
from pollenisator.core.models.tool import Tool
from pollenisator.server.permission import permission
from pollenisator.server.token import encode_token
from pollenisator.core.components.logger_config import logger

ErrorStatus = Tuple[str, int]
ToolInsertResult = TypedDict('ToolInsertResult', {'res': bool, 'iid': ObjectId})
QueueTaskSuccess = TypedDict('QueueTaskSuccess', {'tool_iid': str})
QueueTaskFail = TypedDict('QueueTaskFail', {'tool_iid': str, 'error': str})
QueueTasksResult = TypedDict('QueueTasksResult', {'successes': List[QueueTaskSuccess], 'failures': List[QueueTaskFail]})
response: Any = {}

@permission("pentester")
def setStatus(pentest: str, tool_iid: str, body: Dict[str, Any]) -> Tuple[str, int]:
    """
    Set the status of a tool in the database. If the tool does not exist, an error message is returned. Otherwise, the 
    status of the tool is set to the given status.

    Args:
        pentest (str): The name of the pentest.
        tool_iid (str): The id of the tool whose status will be set.
        body (Dict[str, Any]): A dictionary containing the new status and an optional argument.

    Returns:
        Tuple[str, int]: An error message and status code if an error occurred.
    """
    newStatus = body.get("newStatus", "")
    arg = body.get("arg", "")
    tool_o = Tool.fetchObject(pentest, {"_id":ObjectId(tool_iid)})
    if tool_o is None:
        return "Tool not found", 404
    tool_o = cast(Tool, tool_o)
    tool_o._setStatus(newStatus, arg)
    return "Success", 200

@permission("pentester")
def delete(pentest: str, tool_iid: str) -> Union[Tuple[str, int], int]:
    """
    Delete a tool from the database. If the tool does not exist, an error message is returned. Otherwise, the tool is 
    deleted and the associated check is updated.

    Args:
        pentest (str): The name of the pentest.
        tool_iid (str): The id of the tool to be deleted.

    Returns:
        Union[Tuple[str, int], int]: An error message and status code if an error occurred, 0 if the deletion was 
        unsuccessful, otherwise the result of the deletion operation.
    """
    dbclient = DBClient.getInstance()
    if not dbclient.isUserConnected():
        return "Not connected", 503
    tool_existing = Tool.fetchObject(pentest, {"_id":ObjectId(tool_iid)})
    if tool_existing is None:
        return "Not found", 404
    tool_existing = cast(Tool, tool_existing)
    return tool_existing.deleteFromDb()

@permission("pentester")
def insert(pentest: str, body: Dict[str, Any], **kwargs: Any) -> None:
    """
    Insert a new tool into the database. If the 'base' key is present in the kwargs, it is removed. The tool is then 
    inserted into the database.

    Args:
        pentest (str): The name of the pentest.
        body (Dict[str, Any]): A dictionary containing the tool details.
        **kwargs (Any): Additional keyword arguments.
    """
    if "base" in kwargs:
        del kwargs["base"]
    tool_m = Tool(pentest, body)
    tool_m.addInDb(**kwargs)


@permission("pentester")
def update(pentest: str, tool_iid: str, body: Dict[str, Any]) -> bool:
    """
    Update a tool in the database.

    Args:
        pentest (str): The name of the pentest.
        tool_iid (str): The id of the tool to be updated.
        body (Dict[str, Any]): The new data for the tool.

    Returns:
        bool: True if the update was successful, False otherwise.
    """
    tool_old = Tool.fetchObject(pentest, {"_id":ObjectId(tool_iid)})
    if tool_old is None:
        return False
    tool_old = cast(Tool, tool_old)
    return tool_old.updateInDb(body)

@permission("pentester")
def craftCommandLine(pentest: str, tool_iid: str, commandline_options: str = "") -> Union[Tuple[str, int], Dict[str, str]]:
    """
    Craft the command line for a tool. If the tool does not exist, an error message is returned. If command line options 
    are provided, they are set in the tool. The command object for the tool is fetched and the command line is crafted 
    using the command object and the tool. The plugin for the tool is loaded and the output file name is crafted.

    Args:
        pentest (str): The name of the pentest.
        tool_iid (str): The id of the tool for which the command line will be crafted.
        commandline_options (str, optional): The command line options to be set in the tool. Defaults to "".

    Returns:
        Union[Tuple[str, int], Dict[str, str]]: An error message and status code if an error occurred, otherwise a 
        dictionary containing the crafted command, the file extension and the complete command with output.
    """
    # CHECK TOOL EXISTS
    toolModel = Tool.fetchObject(pentest, {"_id": ObjectId(tool_iid)})
    if toolModel is None:
        return "Tool does not exist : "+str(tool_iid), 404
    toolModel = cast(Tool, toolModel)
    if commandline_options != "":
        toolModel.text = commandline_options
        dbclient = DBClient.getInstance()
        dbclient.updateInDb(pentest, "tools", {"_id":ObjectId(tool_iid)}, {"$set":{"text":commandline_options}}, False, True)
    # GET COMMAND OBJECT FOR THE TOOL
    if toolModel.text == "":
        try:
            command_o: Optional[Union[Command, str]] = Command.fetchObject(pentest, {"_id": ObjectId(toolModel.command_iid)})
            if command_o is None:
                return "Associated command was not found", 404
        except InvalidId:
            return "No command was not found", 404
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
def completeDesiredOuput(pentest: str, tool_iid: str, plugin: str, command_line_options: str) -> Union[Tuple[str, int], Dict[str, str]]:
    """
    Complete the desired output for a tool. If the tool does not exist, an error message is returned. The command to 
    execute is fetched from the tool and the plugin for the tool is loaded. The command is changed using the plugin and 
    the output file name is crafted.

    Args:
        pentest (str): The name of the pentest.
        tool_iid (str): The id of the tool for which the output will be completed.
        plugin (str): The name of the plugin to be loaded.
        command_line_options (str): The command line options to be set in the tool.

    Returns:
        Union[Tuple[str, int], Dict[str, str]]: An error message and status code if an error occurred, otherwise a 
        dictionary containing the completed command line options and the file output extension.
    """
    # CHECK TOOL EXISTS
    toolModel = Tool.fetchObject(pentest, {"_id": ObjectId(tool_iid)})
    if toolModel is None:
        return "Tool does not exist : "+str(tool_iid), 404
    toolModel = cast(Tool, toolModel)
    comm = toolModel.getCommandToExecute(command_line_options)
    mod = loadPlugin(plugin)
    # craft outputfile name
    comm = mod.changeCommand(comm, "|outputDir|", "")
    return {"command_line_options":comm, "ext":mod.getFileOutputExt()}

@permission("user")
def getDesiredOutputForPlugin(body: Dict[str, Any]) -> Union[Tuple[str, int], Dict[str, Union[str, Dict[str, str]]]]:
    """
    Get the desired output for a plugin. If the plugin is 'auto-detect', the plugins are detected using the command line. 
    Otherwise, the plugin is loaded from the body. The command is changed using the plugin and the output file extension 
    is fetched from the plugin.

    Args:
        body (Dict[str, Any]): A dictionary containing the command line and the plugin.

    Returns:
        Dict[str, Union[str, Dict[str, str]]]: A dictionary containing the changed command line options and the output 
        file extensions for the plugins.
    """
    cmdline = body.get("cmdline", None)
    if cmdline is None:
        return "No command line given", 400
    plugin = body.get("plugin", None)
    if plugin is None:
        plugin = "auto-detect"
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
def listPlugins() -> List[Dict[str, Any]]:
    """
    List the plugins available in the plugins directory. For each plugin, the default binary names and the tags are fetched 
    and added to the results.

    Returns:
        List[Dict[str, Union[str, List[str]]]]: A list of dictionaries where each dictionary contains the plugin name, 
        the default binary names for the plugin, and the tags for the plugin.
    """
    dir_path = os.path.dirname(os.path.realpath(__file__))
    path = os.path.join(dir_path, "../../plugins/")
    # Load plugins
    sys.path.insert(0, path)
    results: List[Dict[str, Any]] = []
    plugin_list = os.listdir(path)
    plugin_list = [x[:-3] for x in plugin_list if x.endswith(
        ".py") and x != "__pycache__" and x != "__init__.py" and x != "plugin.py"]
    for plugin in plugin_list:
        mod = loadPlugin(plugin)
        default_bin_names = mod.default_bin_names
        tags = [tag for tag in mod.getTags().values()]
        results.append({"plugin":plugin, "default_bin_names":default_bin_names, "tags":tags, "ext":mod.getFileOutputExt()})
    return results

@permission("pentester")
def importResult(pentest: str, tool_iid: str, upfile: Any, body: Dict[str, Any]) -> Tuple[str, int]:
    """
    Import the result of a tool. The result file is uploaded and the tool is fetched from the database. If the tool has a 
    plugin, the plugin is used to parse the result file. The notes and tags from the plugin are set in the tool and the 
    tool is marked as done. If the tool does not have a plugin, the tool is marked as not done.

    Args:
        pentest (str): The name of the pentest.
        tool_iid (str): The id of the tool whose result will be imported.
        upfile (Any): The result file to be uploaded.
        body (Dict[str, Any]): A dictionary containing additional data.

    Returns:
        Union[Tuple[str, int], str]: An error message and status code if an error occurred, otherwise a success message.
    """
    dbclient = DBClient.getInstance()
    #STORE FILE
    res, status, filepath = dbclient.do_upload(pentest, tool_iid, "result", upfile)
    if status != 200:
        return res, status
    # Analyze
    toolModel = Tool.fetchObject(pentest, {"_id": ObjectId(tool_iid)})
    if toolModel is None:
        return "Tool not found", 404
    toolModel = cast(Tool, toolModel)
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
                toolModel.addTag(tag)
            toolModel.markAsDone(filepath)
            # And update the tool in database
            update(pentest, tool_iid, toolModel.getData())
            # Upload file to SFTP
            msg = "TASK SUCCESS : "+toolModel.name
        except IOError as _e:
            toolModel.addTag(Tag("no-output", "red", "error", "Failed to read results file"))
            toolModel.notes = "Failed to read results file"
            toolModel.markAsDone()
            update(pentest, tool_iid, toolModel.getData())
    else:
        msg = "TASK FAILED (no plugin found) : "+toolModel.name
        toolModel.markAsNotDone()
        update(pentest, tool_iid, toolModel.getData())
        raise Exception(msg)
    return "Success", 200


@permission("pentester")
def queueTasks(pentest: str, body: List[str], **kwargs: Any) -> QueueTasksResult:
    """
    Queue tasks for a pentest. The tasks are fetched from the body and added to the queue. If a task is successfully added 
    to the queue, it is added to the successes list. If a task fails to be added to the queue, it is added to the failures 
    list along with the error message.

    Args:
        pentest (str): The name of the pentest.
        body (List[str]): A list of task ids to be added to the queue.
        **kwargs (Any): Additional keyword arguments.

    Returns:
        QueueTasksResult: A dictionary containing the successes and 
        failures of adding tasks to the queue.
    """
    if not isinstance(body, list):
        return {"successes":[], "failures":[{"tool_iid":"", "error":"Body is not a list"}]}
    tools_iids = set()
    for tool_iid in body:
        if isinstance(tool_iid, str) and tool_iid.startswith("ObjectId|"):
            tool_iid = tool_iid[9:]
        try:
            tools_iids.add(ObjectId(tool_iid))
        except InvalidId:
            return {"successes":[], "failures":[{"tool_iid":tool_iid, "error":"Invalid ObjectId"}]}
    return Tool.queueTasks(pentest, tools_iids)


@permission("pentester")
def unqueueTasks(pentest: str, body: List[str], **kwargs: Any) -> QueueTasksResult:
    """
    Remove tasks from the queue for a pentest. The tasks are fetched from the body and removed from the queue. If a task 
    is successfully removed from the queue, it is added to the successes list. If a task fails to be removed from the 
    queue, it is added to the failures list along with the error message.

    Args:
        pentest (str): The name of the pentest.
        body (List[str]): A list of task ids to be removed from the queue.
        **kwargs (Any): Additional keyword arguments.

    Returns:
        QueueTasksResult: A dictionary containing the successes and 
        failures of removing tasks from the queue.
    """
    if not isinstance(body, list):
        return {"successes":[], "failures":[{"tool_iid":"", "error":"Body is not a list"}]}
    tools_iids = set()
    for tool_iid in body:
        if isinstance(tool_iid, str) and tool_iid.startswith("ObjectId|"):
            tool_iid = tool_iid[9:]
        try:
            tools_iids.add(ObjectId(tool_iid))
        except InvalidId:
            return {"successes":[], "failures":[{"tool_iid":tool_iid, "error":"Invalid ObjectId"}]}
    return Tool.unqueueTasks(pentest, tools_iids)


@permission("pentester")
def clearTasks(pentest: str, **kwargs: Any):
    """
    Remove all tasks queue for pentest given

    Args:
        pentest (str): given to pentest to clear tasks
    """
    Tool.clearQueue(pentest)


@permission("pentester")
def getQueue(pentest: str) -> List[Dict[str, Any]]:
    """
    Get the queue for a pentest. The queue is fetched from the database and the tools in the queue are fetched. The 
    commands for the tools are also fetched. For each tool in the queue, the tool data is fetched and if the tool text is 
    empty, the command text is set as the tool text. The tool data is then added to the results.

    Args:
        pentest (str): The name of the pentest.

    Returns:
        List[Dict[str, Any]]: A list of dictionaries where each dictionary contains the data for a tool in the queue.
    """
    dbclient = DBClient.getInstance()
    res: List[Dict[str, Any]] = []
    queue = dbclient.findInDb(pentest, "autoscan", {"type":"queue"}, False)
    if queue is not None:
        tools = queue["tools"]
        tools_objects = Tool.fetchObjects(pentest, {"_id": {"$in": [ObjectId(tool_info.get("iid")) for tool_info in tools]}})
        if tools_objects is None:
            return res
        commands = Command.fetchObjects(pentest, {})
        commands_dict = {str(command.getId()):command for command in commands}
        for tool in tools_objects:
            tool = cast(Tool, tool)
            tool_data = {}
            tool_data = tool.getData()
            if tool.text == "":
                command = commands_dict.get(str(tool.command_iid))
                if command is not None:
                    try:
                        tool_data["text"] = command.text
                    except AttributeError:
                        tool_data["text"] = ""
            res.append(tool_data)
    return res

def isLaunchable(pentest: str, tool_iid: ObjectId, authorized_commands: Optional[List[str]], force: bool = False) -> Tuple[str, int]:
    """
    Check if a tool is launchable. The tool and its command are fetched from the database. If the command is not 
    authorized for autoscan and force is not set, an error message is returned. If the tool or the command do not exist, 
    an error message is returned. The workers that support the command plugin are fetched from the database. If no worker 
    is available to launch the tool, an error message is returned. If a worker is available, the socket for the worker is 
    fetched from the database. If the socket does not exist, an error message is returned.

    Args:
        pentest (str): The name of the pentest.
        tool_iid (ObjectId): The id of the tool to be launched.
        authorized_commands (Optional[List[str]]): A list of authorized commands for autoscan.
        force (bool, optional): Whether to force the launch of the tool. Defaults to False.

    Returns:
        Tuple[str, int]: An error message and status code if an error occurred, otherwise the socket id for 
        the worker that will launch the tool.
    """
    launchableTool = Tool.fetchObject(pentest, {"_id": ObjectId(tool_iid)})
    if launchableTool is None:
        logger.debug("Error in launch task : not found : %s",str(tool_iid))
        return "Tool not found", 404
    launchableTool = cast(Tool, launchableTool)
    return launchableTool.isLaunchable(authorized_commands, force)

    
@permission("pentester")
def runTask(pentest: str, tool_iid: ObjectId, **kwargs: Any) -> ErrorStatus:
    """
    Run a task. The task is checked if it is launchable. If the task is not launchable, an error message and status code 
    are returned. If the task is launchable, the task is launched using the launchTask function.

    Args:
        pentest (str): The name of the pentest.
        tool_iid (ObjectId): The id of the tool to be run.
        **kwargs (Any): Additional keyword arguments.

    Returns:
        ErrorStatus: An error message and status code if an error occurred, otherwise a success message.
    """
    msg, statuscode = isLaunchable(pentest, ObjectId(tool_iid), None)
    if statuscode != 200:
        return msg, statuscode
    socket_sid = msg
    encoded = encode_token(kwargs["token_info"])
    Tool.launchTask(pentest, ObjectId(tool_iid), socket_sid, encoded)
    return "Success", 200

@permission("pentester")
def getProgress(pentest: str, tool_iid: str) -> Tuple[Union[bool, str], int]:
    """
    Get the progress of a tool. The tool is fetched from the database and its status is checked. If the tool is done, 
    True is returned. If the tool is not running, an error message is returned. The workers are fetched from the database 
    and the worker running the tool is checked. If the worker is not running, an error message is returned. The socket for 
    the worker is fetched from the database and a getProgress event is emitted to the worker. The response from the worker 
    is waited for and returned.

    Args:
        pentest (str): The name of the pentest.
        tool_iid (str): The id of the tool whose progress will be gotten.

    Returns:
        Union[Tuple[str, int], bool]: An error message and status code if an error occurred, True if tool is done, otherwise the 
        progress of the tool and a success status code.
    """
    dbclient = DBClient.getInstance()
    tool = Tool.fetchObject(pentest, {"_id": ObjectId(tool_iid)})
    logger.info("Trying to get progress of task %s", str(tool))
    if tool is None:
        return "Tool not found", 404
    tool = cast(Tool, tool)
    if "done" in tool.status:
        return True, 200
    elif "running"  not in tool.status:
        return "Tool is not running", 400
    workers = dbclient.getWorkers({})
    if workers is None:
        workerNames = []
    else:
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
    response = {}
    @sm.socketio.event
    def getProgressResult(data):
        global response
        response = data
        if data.get("result", "") is None:
            response = {"result": b""}
    start_time = time.time()
    while time.time() - start_time < 3:
        if len(response) == 0 or response is None:
            time.sleep(0.1)
        else:
            break
    if len(response) == 0 or response is None:
        return "Could not get worker progress", 404
    logger.info('Received response: %s' , str(response))
    if isinstance(response["result"], str) or isinstance(response["result"], bool):
        return response["result"], 200
    elif isinstance(response["result"], bytes):
        return response["result"].decode(), 200
    else:
        return "Invalid response of the worker", 400


@permission("pentester")
def stopTask(pentest: str, tool_iid: str, body: Dict[str, Any]) -> ErrorStatus:
    """
    Stop a task. The task is fetched from the database and checked if it is stoppable. If the task is not stoppable, an 
    error message is returned. The workers are fetched from the database and the worker running the task is checked. If 
    the worker is not running, an error message is returned. The socket for the worker is fetched from the database and a 
    stopCommand event is emitted to the worker. If forceReset is set in the body, the task is marked as not done.

    Args:
        pentest (str): The name of the pentest.
        tool_iid (str): The id of the tool to be stopped.
        body (Dict[str, Any]): A dictionary containing additional data.

    Returns:
       ErrorStatus: An error message and status code if an error occurred, otherwise a 
        success message and status code.
    """
    tool_o = Tool.fetchObject(pentest, {"_id": ObjectId(tool_iid)})
    tool_o = cast(Tool, tool_o)
    forceReset = body.get("forceReset", False)
    return tool_o.stopTask(forceReset=forceReset)


@permission("pentester")
def getDetailedString(pentest: str, tool_iid: str) -> Tuple[str, int]:
    """
    Get the detailed string of a tool. The tool is fetched from the database using its id. If the tool does not exist, an 
    error message is returned. If the tool exists, the detailed string of the tool is returned.

    Args:
        pentest (str): The name of the pentest.
        tool_iid (str): The id of the tool whose detailed string will be gotten.

    Returns:
        Union[Tuple[str, int], str]: An error message and status code if an error occurred, otherwise the detailed string 
        of the tool.
    """
    tool = Tool.fetchObject(pentest, {"_id": ObjectId(tool_iid)})
    if tool is None:
        return "Tool not found", 404
    tool = cast(Tool, tool)
    return tool.getDetailedString(), 200

def getNbOfLaunchedCommand(pentest: str, worker: str, command_iid: ObjectId) -> int:
    """
    Get the total number of running commands which have the given command name.

    Args:
        pentest (str): The name of the pentest.
        worker (str): The worker's name.
        command_iid (ObjectId): The command iid to count running tools.

    Returns:
        int: Return the total of running tools with this command's name as an integer.
    """
    dbclient = DBClient.getInstance()
    t = dbclient.countInDb(pentest, "tools", {"command_iid": ObjectId(command_iid), "scanner_ip": worker, "dated": {
                            "$ne": "None"}, "datef": "None"})
    if t is not None:
        return t
    return 0
