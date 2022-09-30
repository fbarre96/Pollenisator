"""Module for orchestrating an automatic scan. Must be run in a separate thread/process."""
import logging
import time
from threading import Thread
from datetime import datetime
from bson.objectid import ObjectId
import pollenisator.core.Components.Utils as Utils
from pollenisator.core.Components.mongo import MongoCalendar
from pollenisator.server.ServerModels.Interval import ServerInterval
from pollenisator.server.ServerModels.Command import ServerCommand
from pollenisator.server.ServerModels.CommandGroup import ServerCommandGroup
from pollenisator.server.ServerModels.Tool import ServerTool, launchTask, stopTask
from pollenisator.server.ServerModels.Scope import ServerScope
from pollenisator.server.ServerModels.Ip import ServerIp
from pollenisator.server.permission import permission
from pollenisator.server.token import encode_token

    
@permission("pentester")
def startAutoScan(pentest, **kwargs):
    mongoInstance = MongoCalendar.getInstance()
    mongoInstance.connectToDb(pentest)
    autoscanRunning = mongoInstance.find("autoscan", {"special":True}, False) is not None
    if autoscanRunning:
        return "An auto scan is already running", 403
    workers = mongoInstance.getWorkers({"pentest":pentest})
    if workers is None:
        return "No worker registered for this pentest", 404
    mongoInstance.insert("autoscan", {"start":datetime.now(), "special":True})
    encoded = encode_token(kwargs["token_info"])
    autoscan = Thread(target=autoScan, args=(pentest, encoded))
    try:
        autoscan.start()
    except(KeyboardInterrupt, SystemExit):
        mongoInstance.delete("autoscan", {}, True)
    return "Success"

def autoScan(pentest, endoded_token):
    """
    Search tools to launch within defined conditions and attempts to launch them this  worker.
    Gives a visual feedback on stdout

    Args:
        pentest: The database to search tools in
    """
    mongoInstance = MongoCalendar.getInstance()
    mongoInstance.connectToDb(pentest)
    check = True
    try:
        while check:
            queue = [] # reinit queue each time as some tools may be finished / canceled / errored
            launchableTools = findLaunchableTools(pentest)
            launchableTools.sort(key=lambda tup: (int(tup["timedout"]), int(tup["priority"])))
            for launchableTool in launchableTools:
                check = getAutoScanStatus(pentest)
                if not check:
                    break
                if str(launchableTool["tool"].getId()) not in queue:
                    queue.append(str(launchableTool["tool"].getId()))
                    res, statuscode = launchTask(pentest, launchableTool["tool"].getId(), {"checks":True}, worker_token=endoded_token)
                
            check = getAutoScanStatus(pentest)
            time.sleep(3)
    except(KeyboardInterrupt, SystemExit):
        logging.info("stop autoscan : Kill received...")
        mongoInstance.delete("autoscan", {}, True)
    except Exception as e:
        logging.error(str(e))

@permission("pentester")
def stopAutoScan(pentest):
    mongoInstance = MongoCalendar.getInstance()
    mongoInstance.connectToDb(pentest)
    toolsRunning = []
    workers = mongoInstance.getWorkers({"pentest":pentest})
    for worker in workers:
        tools = mongoInstance.find("tools", {"scanner_ip": worker["name"], "status":"running"}, True)
        for tool in tools:
            toolsRunning.append(tool["_id"])
    mongoInstance.delete("autoscan", {}, True)
    for toolId in toolsRunning:
        res, msg = stopTask(pentest, toolId, {"forceReset":True})
    return "Success"

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
    time_compatible_waves_id = searchForAddressCompatibleWithTime(pentest)
    for wave_id in time_compatible_waves_id:
        #get not done tools inside wave
        commandsLaunchableWave = getNotDoneTools(pentest, wave_id)
        for toolId, toolModel in commandsLaunchableWave.items():
            if "error" in toolModel.status:
                continue
            command = toolModel.getCommand()
            if command is None:
                prio = 0
            else:
                prio = int(command.get("priority", 0))
            toolsLaunchable.append(
                {"tool": toolModel, "name": str(toolModel), "priority": prio, "timedout":"timedout" in toolModel.status})
    return toolsLaunchable


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
    notDoneTools = dict()
    # get not done tools that are not IP based (scope)
    tools = ServerTool.fetchObjects(pentest, {"wave": waveName, "ip": "", "dated": "None", "datef": "None"})
    for tool in tools:
        notDoneTools[tool.getId()] = tool
    # fetch scopes to get IPs in scope
    scopes = ServerScope.fetchObjects(pentest, {"wave": waveName})
    for scope in scopes:
        scopeId = scope.getId()
        # get IPs in scope
        ips = ServerIp.getIpsInScope(pentest, scopeId)
        for ip in ips:
            # fetch IP level and below (e.g port) tools
            tools = ServerTool.fetchObjects(pentest, {
                                        "wave": waveName, "ip": ip.ip, "dated": "None", "datef": "None"})
            for tool in tools:
                notDoneTools[tool.getId()] = tool
    return notDoneTools

