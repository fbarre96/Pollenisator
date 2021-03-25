"""Module for orchestrating an automatic scan. Must be run in a separate thread/process."""
import time
from multiprocessing import Process
from datetime import datetime
from bson.objectid import ObjectId
import core.Components.Utils as Utils
from core.Components.mongo import MongoCalendar
from server.ServerModels.Interval import ServerInterval
from server.ServerModels.Command import ServerCommand
from server.ServerModels.CommandGroup import ServerCommandGroup
from server.ServerModels.Tool import ServerTool, getNbOfLaunchedCommand, launchTask, stopTask
from server.ServerModels.Scope import ServerScope
from server.ServerModels.Ip import ServerIp
from server.permission import permission
from server.token import encode_token

@permission("pentester")
def startAutoScan(pentest, **kwargs):
    token = encode_token(kwargs["token_info"])
    mongoInstance = MongoCalendar.getInstance()
    mongoInstance.connectToDb(pentest)
    autoscanRunning = mongoInstance.find("autoscan", {"special":True}, False) is not None
    if autoscanRunning:
        return "An auto scan is already running", 403
    workers = mongoInstance.getWorkers({"pentests":pentest})
    if workers is None:
        return "No worker registered for this pentest", 404
    mongoInstance.insert("autoscan", {"start":datetime.now(), "special":True})
    keywords = kwargs
    autoscan = Process(target=autoScan, args=(pentest,), kwargs=keywords)
    try:
        autoscan.start()
    except(KeyboardInterrupt, SystemExit):
        mongoInstance.delete("autoscan", {}, True)

@permission("pentester")
def autoScan(pentest, **kwargs):
    """
    Search tools to launch within defined conditions and attempts to launch them this  worker.
    Gives a visual feedback on stdout

    Args:
        pentest: The database to search tools in
    """
    mongoInstance = MongoCalendar.getInstance()
    mongoInstance.connectToDb(pentest)
    check = True
    if "body" in kwargs:
        del kwargs["body"]
    try:
        while check:
            launchableTools, waiting = findLaunchableTools(pentest)
            launchableTools.sort(key=lambda tup: (tup["timedout"], int(tup["priority"])))
            #TODO CHECK SPACE 
            for launchableTool in launchableTools:
                res, statuscode = launchTask(pentest, launchableTool["tool"].getId(), {"checks":True, "plugin":""}, **kwargs)
            check = getAutoScanStatus(pentest)
            time.sleep(3)
    except(KeyboardInterrupt, SystemExit):
        print("stop autoscan : Kill received...")
        mongoInstance.delete("autoscan", {}, True)

@permission("pentester")
def stopAutoScan(pentest):
    mongoInstance = MongoCalendar.getInstance()
    mongoInstance.connectToDb(pentest)
    toolsRunning = []
    workers = mongoInstance.getWorkers({"pentests":pentest})
    for worker in workers:
        tools = mongoInstance.find("tools", {"scanner_ip": worker["name"]}, True)
        for tool in tools:
            toolsRunning.append(tool["_id"])
    mongoInstance.delete("autoscan", {}, True)
    for toolId in toolsRunning:
        res, msg = stopTask(pentest, toolId, {"forceReset":True})
        print("STOPTASK : "+str(msg))

@permission("pentester")
def getAutoScanStatus(pentest):
    #commandsRunning = mongoInstance.aggregate("tools", [{"$match": {"datef": "None", "dated": {
    #        "$ne": "None"}, "scanner_ip": {"$ne": "None"}}}, {"$group": {"_id": "$name", "count": {"$sum": 1}}}])
    mongoInstance = MongoCalendar.getInstance()
    mongoInstance.connectToDb(pentest)
    return mongoInstance.find("autoscan", {"special":True}, False) is not None


def findLaunchableTools(pentest):
    """ 
    Try to find tools that matches all criteria.
    Args:
        workerName: the current working worker
    Returns:
        A tuple with two values:
            * A list of launchable tools as dictionary with values _id, name and priority
            * A dictionary of waiting tools with tool's names as keys and integer as value.
    """
    toolsLaunchable = []
    waiting = {}
    time_compatible_waves_id = searchForAddressCompatibleWithTime(pentest)
    for wave_id in time_compatible_waves_id:
        commandsLaunchableWave = getNotDoneTools(pentest, wave_id)
        for tool in commandsLaunchableWave:
            toolModel = ServerTool.fetchObject(pentest, {"_id": tool})
            try:
                waiting[str(toolModel)] += 1
            except KeyError:
                waiting[str(toolModel)] = 1
            if "error" in toolModel.status:
                continue
            command = toolModel.getCommand()
            if command is None:
                prio = 0
            else:
                prio = int(command.get("priority", 0))
            toolsLaunchable.append(
                {"tool": toolModel, "name": str(toolModel), "priority": prio, "timedout":"timedout" in toolModel.status})

    return toolsLaunchable, waiting


def searchForAddressCompatibleWithTime(pentest):
    """
    Return a list of wave which have at least one interval fitting the actual time.

    Returns:
        A set of wave name
    """
    waves_to_launch = set()
    intervals = ServerInterval.fetchObjects(pentest, {})
    for intervalModel in intervals:
        if Utils.fitNowTime(intervalModel.dated, intervalModel.datef):
            waves_to_launch.add(intervalModel.wave)
    return waves_to_launch

def getNotDoneTools(pentest, waveName):
    """Returns a set of tool mongo ID that are not done yet.
    """
    notDoneTools = set()
    tools = ServerTool.fetchObjects(pentest, {"wave": waveName, "ip": "", "dated": "None", "datef": "None"})
    for tool in tools:
        notDoneTools.add(tool.getId())
    scopes = ServerScope.fetchObjects(pentest, {"wave": waveName})
    for scope in scopes:
        scopeId = scope.getId()
        ips = ServerIp.getIpsInScope(pentest, scopeId)
        for ip in ips:
            tools = ServerTool.fetchObjects(pentest, {
                                        "wave": waveName, "ip": ip.ip, "dated": "None", "datef": "None"})
            for tool in tools:
                notDoneTools.add(tool.getId())
    return notDoneTools

