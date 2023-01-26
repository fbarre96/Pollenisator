"""Module for orchestrating an automatic scan. Must be run in a separate thread/process."""
from pollenisator.core.components.socketmanager import SocketManager
from pollenisator.core.components.logger_config import logger
import time
from threading import Thread
from datetime import datetime
from bson.objectid import ObjectId
import pollenisator.core.components.utils as utils
from pollenisator.core.components.mongo import MongoCalendar
from pollenisator.server.servermodels.interval import ServerInterval
from pollenisator.server.servermodels.command import ServerCommand
from pollenisator.server.modules.cheatsheet.checkinstance import CheckInstance
from pollenisator.server.modules.cheatsheet.cheatsheet import CheckItem
from pollenisator.server.servermodels.tool import ServerTool, launchTask, stopTask
from pollenisator.server.servermodels.scope import ServerScope
from pollenisator.server.servermodels.ip import ServerIp
from pollenisator.server.permission import permission
from pollenisator.server.token import encode_token

    
@permission("pentester")
def startAutoScan(pentest, **kwargs):
    mongoInstance = MongoCalendar.getInstance()
    autoscanRunning = mongoInstance.findInDb(pentest, "autoscan", {"special":True}, False) is not None
    if autoscanRunning:
        return "An auto scan is already running", 403
    workers = mongoInstance.getWorkers({"pentest":pentest})
    if workers is None:
        return "No worker registered for this pentest", 404
    mongoInstance.insertInDb(pentest, "autoscan", {"start":datetime.now(), "special":True})
    encoded = encode_token(kwargs["token_info"])
    autoscan = Thread(target=autoScan, args=(pentest, encoded))
    try:
        logger.debug("Autoscan : start")
        autoscan.start()
    except(KeyboardInterrupt, SystemExit):
        mongoInstance.deleteFromDb(pentest, "autoscan", {}, True)
    return "Success"

def autoScan(pentest, endoded_token):
    """
    Search tools to launch within defined conditions and attempts to launch them this  worker.
    Gives a visual feedback on stdout

    Args:
        pentest: The database to search tools in
    """
    mongoInstance = MongoCalendar.getInstance()
    check = True
    try:
        while check:
            logger.debug("Autoscan : loop")
            #check_on_running_tools(pentest)
            queue = [] # reinit queue each time as some tools may be finished / canceled / errored
            launchableTools = findLaunchableTools(pentest)
            logger.debug("Autoscan : launchable tools: "+str(len(launchableTools)))
            launchableTools.sort(key=lambda tup: (int(tup["timedout"]), int(tup["priority"])))
            for launchableTool in launchableTools:
                logger.debug("Autoscan : loop")
                check = getAutoScanStatus(pentest)
                if not check:
                    break
                if str(launchableTool["tool"].getId()) not in queue:
                    queue.append(str(launchableTool["tool"].getId()))
                    logger.debug("Autoscan : launch task tools: "+str(launchableTool["tool"].getId()))
                    res, statuscode = launchTask(pentest, launchableTool["tool"].getId(),  worker_token=endoded_token)
                
            check = getAutoScanStatus(pentest)
            time.sleep(3)
    except(KeyboardInterrupt, SystemExit):
        logger.debug("Autoscan : EXIT by expected EXCEPTION (exit or interrupt)")
        logger.info("stop autoscan : Kill received...")
        mongoInstance.deleteFromDb(pentest, "autoscan", {}, True)
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
    mongoInstance = MongoCalendar.getInstance()
    toolsRunning = []
    workers = mongoInstance.getWorkers({"pentest":pentest})
    for worker in workers:
        tools = mongoInstance.findInDb(pentest, "tools", {"scanner_ip": worker["name"], "status":"running"}, True)
        for tool in tools:
            toolsRunning.append(tool["_id"])
    mongoInstance.deleteFromDb(pentest, "autoscan", {}, True)
    for toolId in toolsRunning:
        res, msg = stopTask(pentest, toolId, {"forceReset":True})
    return "Success"

@permission("pentester")
def getAutoScanStatus(pentest):
    #commandsRunning = mongoInstance.aggregate("tools", [{"$match": {"datef": "None", "dated": {
    #        "$ne": "None"}, "scanner_ip": {"$ne": "None"}}}, {"$group": {"_id": "$name", "count": {"$sum": 1}}}])
    mongoInstance = MongoCalendar.getInstance()
    return mongoInstance.findInDb(pentest, "autoscan", {"special":True}, False) is not None


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
    mongoInstance = MongoCalendar.getInstance()
    check_items = list(CheckItem.fetchObjects({"type":"auto_commands"}))
    check_items.sort(key=lambda c: c.priority)
    
    authorized_diff_of_prio = 2 #TODO not hardcode  parameter

    #get not done tools inside wave
    first_command_group_launched_prio = None
    for check_item in check_items:
        if first_command_group_launched_prio is not None and \
            check_item.priority > first_command_group_launched_prio+ authorized_diff_of_prio: # take only prio and prio+1
            break
        launched = 0
        count_running_tools = 0

        check_instances = CheckInstance.fetchObjects(pentest, {"check_iid":str(check_item._id)})
        for check_instance in check_instances:
            notDoneToolsInCheck = getNotDoneTools(pentest, check_instance)
            count_running_tools += mongoInstance.countInDb(pentest, "tools", {"check_iid":str(check_instance._id), "status":"running"})
            
            for toolId, toolModel in notDoneToolsInCheck.items():
                if count_running_tools + launched >= check_item.max_thread:
                    logger.info(f"Can't launch anymore of check {check_item.title}")
                    break
                if "error" in toolModel.status:
                    continue
                toolsLaunchable.append(
                    {"tool": toolModel, "name": str(toolModel), "priority":int(check_item.priority), "timedout":"timedout" in toolModel.status})
                launched += 1
        if launched > 0 or count_running_tools > 0 and first_command_group_launched_prio is None:
            first_command_group_launched_prio = check_item.priority
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

def getNotDoneTools(pentest, check_instance):
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

