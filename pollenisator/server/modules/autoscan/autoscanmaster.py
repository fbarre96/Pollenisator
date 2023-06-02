"""Module for orchestrating an automatic scan. Must be run in a separate thread/process."""
from pollenisator.core.components.socketmanager import SocketManager
from pollenisator.core.components.logger_config import logger
import time
from threading import Thread
from datetime import datetime
from bson.objectid import ObjectId
import pollenisator.core.components.utils as utils
from pollenisator.core.components.mongo import DBClient
from pollenisator.server.servermodels.interval import ServerInterval
from pollenisator.server.servermodels.command import ServerCommand
from pollenisator.server.modules.cheatsheet.checkinstance import CheckInstance
from pollenisator.server.modules.cheatsheet.cheatsheet import CheckItem
from pollenisator.server.servermodels.tool import ServerTool, launchTask, stopTask, isLaunchable, queueTasks
from pollenisator.server.servermodels.scope import ServerScope
from pollenisator.server.servermodels.ip import ServerIp
from pollenisator.server.permission import permission
from pollenisator.server.token import encode_token

    
@permission("pentester")
def startAutoScan(pentest, **kwargs):
    dbclient = DBClient.getInstance()
    autoscanRunning = dbclient.findInDb(pentest, "autoscan", {"special":True}, False) is not None
    if autoscanRunning:
        return "An auto scan is already running", 403
    workers = dbclient.getWorkers({"pentest":pentest})
    if workers is None:
        return "No worker registered for this pentest", 404
    dbclient.insertInDb(pentest, "autoscan", {"start":datetime.now(), "special":True})
    encoded = encode_token(kwargs["token_info"])
    # queue auto commands
    tools_lauchable = findLaunchableTools(pentest)
    queueTasks(pentest, [tool_model["tool"].getId() for tool_model in tools_lauchable])
    autoscan = Thread(target=autoScan, args=(pentest, encoded))
    try:
        logger.debug("Autoscan : start")
        autoscan.start()
    except(KeyboardInterrupt, SystemExit):
        dbclient.deleteFromDb(pentest, "autoscan", {}, True)
    return "Success"

def autoScan(pentest, endoded_token):
    """
    Search tools to launch within defined conditions and attempts to launch them this  worker.
    Gives a visual feedback on stdout

    Args:
        pentest: The database to search tools in
    """
    dbclient = DBClient.getInstance()
    check = True
    try:
        while check:
            autoscan_threads = dbclient.findInDb(pentest, "settings", {"key":"autoscan_threads"}, False)
            autoscan_threads = 4 if autoscan_threads is None else int(autoscan_threads["value"])

            running_tools_count = dbclient.countInDb(pentest, "tools", {"status":"running"})
            logger.debug("Autoscan : loop")
            #check_on_running_tools(pentest)
            if autoscan_threads - running_tools_count <= 0:
                time.sleep(6)
                logger.debug("Autoscan : skip round because too many running tools ")
                check = getAutoScanStatus(pentest)
                continue
            launchableTools = []
            queue = dbclient.findInDb(pentest, "autoscan", {"type":"queue"}, False)
            if queue is None:
                launchableTools = []
            else:
                launchableTools = queue["tools"]
            logger.debug("Autoscan : launchable tools: "+str(len(launchableTools)))
            #launchableTools.sort(key=lambda tup: (int(tup["timedout"]), int(tup["priority"])))
            toLaunch = []
            
            for launchableTool in launchableTools:
                logger.debug("Autoscan : loop")
                check = getAutoScanStatus(pentest)
                if not check:
                    break
                if autoscan_threads - len(toLaunch) - running_tools_count <= 0:
                    break
                logger.debug("Autoscan : launch task tools: "+str(launchableTool))
                msg, statuscode = isLaunchable(pentest, launchableTool)
                if statuscode == 404:
                    dbclient.updateInDb(pentest, "autoscan", {"type":"queue"}, {"$pull":{"tools":launchableTool}})
                    tool_o = ServerTool.fetchObject(pentest, {"_id":ObjectId(launchableTool)})
                    if tool_o is not None:
                        tool_o.markAsError()
                elif statuscode == 200:
                    dbclient.updateInDb(pentest, "autoscan", {"type":"queue"}, {"$pull":{"tools":launchableTool}})
                    toLaunch.append([launchableTool, msg])
                    # the tool will be launched, we can remove it from the queue, let the worker set it as running
            for tool in toLaunch:
                launchTask(pentest, tool[0], tool[1], endoded_token)
            check = getAutoScanStatus(pentest)
            time.sleep(6)
    except(KeyboardInterrupt, SystemExit):
        logger.debug("Autoscan : EXIT by expected EXCEPTION (exit or interrupt)")
        logger.info("stop autoscan : Kill received...")
        dbclient.deleteFromDb(pentest, "autoscan", {}, True)
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        print(tb)
        logger.exception(e)
        logger.debug("autoscan :"+tb)
        logger.error(str(e))




@permission("pentester")
def stopAutoScan(pentest):
    logger.debug("Autoscan : stop autoscan received ")
    dbclient = DBClient.getInstance()
    toolsRunning = []
    workers = dbclient.getWorkers({"pentest":pentest})
    for worker in workers:
        tools = dbclient.findInDb(pentest, "tools", {"scanner_ip": worker["name"], "status":"running"}, True)
        for tool in tools:
            toolsRunning.append(tool["_id"])
    dbclient.deleteFromDb(pentest, "autoscan", {}, True)
    for toolId in toolsRunning:
        res, msg = stopTask(pentest, toolId, {"forceReset":True})
    return "Success"

@permission("pentester")
def getAutoScanStatus(pentest):
    #commandsRunning = dbclient.aggregate("tools", [{"$match": {"datef": "None", "dated": {
    #        "$ne": "None"}, "scanner_ip": {"$ne": "None"}}}, {"$group": {"_id": "$name", "count": {"$sum": 1}}}])
    dbclient = DBClient.getInstance()
    return dbclient.findInDb(pentest, "autoscan", {"special":True}, False) is not None


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
    if time_compatible_waves_id is None:
        return toolsLaunchable
    dbclient = DBClient.getInstance()
    check_items = list(CheckItem.fetchObjects({"type":"auto_commands"}))
    check_items.sort(key=lambda c: c.priority)
    #get not done tools inside wave
    for check_item in check_items:
        check_instances = CheckInstance.fetchObjects(pentest, {"check_iid":str(check_item._id)})
        for check_instance in check_instances:
            notDoneToolsInCheck = getNotDoneToolsPerScope(pentest, check_instance)
            for toolId, toolModel in notDoneToolsInCheck.items():
                if "error" in toolModel.status:
                    continue
                toolsLaunchable.append(
                    {"tool": toolModel, "name": str(toolModel), "priority":int(check_item.priority), "timedout":"timedout" in toolModel.status})
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
        if utils.fitNowTime(intervalModel.dated, intervalModel.datef):
            waves_to_launch.add(intervalModel.wave)
    return waves_to_launch

def getNotDoneToolsPerScope(pentest, check_instance):
    """Returns a set of tool mongo ID that are not done yet.
    """
    #
    notDoneTools = dict()
    # get not done tools that are not IP based (scope)
    tools = ServerTool.fetchObjects(pentest, {"check_iid":str(check_instance._id), "ip":"", "dated": "None", "datef": "None"})
    for tool in tools:
        notDoneTools[tool.getId()] = tool
    # fetch scopes to get IPs in scope
    scopes = ServerScope.fetchObjects(pentest, {})
    for scope in scopes:
        scopeId = scope.getId()
        # get IPs in scope
        ips = ServerIp.getIpsInScope(pentest, scopeId)
        for ip in ips:
            # fetch IP level and below (e.g port) tools
            tools = ServerTool.fetchObjects(pentest, {"check_iid":str(check_instance._id), "ip": ip.ip, "dated": "None", "datef": "None"})
            for tool in tools:
                notDoneTools[tool.getId()] = tool
    return notDoneTools

