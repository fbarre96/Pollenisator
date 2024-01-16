"""Module for orchestrating an automatic scan. Must be run in a separate thread/process."""
from pollenisator.core.components.socketmanager import SocketManager
from pollenisator.core.components.logger_config import logger
import time
from threading import Thread
from datetime import datetime
from bson.objectid import ObjectId
from bson.errors import InvalidId
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
from itertools import chain


@permission("pentester")
def startAutoScan(pentest, body, **kwargs):
    dbclient = DBClient.getInstance()
    authorized_commands = body.get("command_iids", [])
    autoqueue = body.get("autoqueue", False)
    for authorized_command in authorized_commands:
        try:
            iid = ObjectId(authorized_command)
        except InvalidId:
            return "Invalid command id", 400
    autoscanRunning = dbclient.findInDb(
        pentest, "autoscan", {"special": True}, False) is not None
    if autoscanRunning:
        return "An auto scan is already running", 403
    workers = dbclient.getWorkers({"pentest": pentest})
    if workers is None:
        return "No worker registered for this pentest", 404
    dbclient.insertInDb(pentest, "autoscan", {"start": datetime.now(
    ), "special": True, "authorized_commands": authorized_commands})
    encoded = encode_token(kwargs["token_info"])
    # queue auto commands
    tools_lauchable = findLaunchableTools(pentest)
    queueTasks(pentest, [tool_model["tool"].getId()
               for tool_model in tools_lauchable])
    autoscan = Thread(target=autoScan, args=(pentest, encoded, autoqueue))
    try:
        logger.debug("Autoscan : start")
        autoscan.start()
    except (KeyboardInterrupt, SystemExit):
        dbclient.deleteFromDb(pentest, "autoscan", {}, True)
    return "Success"


def autoScan(pentest, endoded_token, autoqueue):
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
            autoscan_threads = dbclient.findInDb(
                pentest, "settings", {"key": "autoscan_threads"}, False)
            autoscan_threads = 4 if autoscan_threads is None else int(
                autoscan_threads["value"])

            running_tools_count = dbclient.countInDb(
                pentest, "tools", {"status": "running"})
            # check_on_running_tools(pentest)
            if autoscan_threads - running_tools_count <= 0:
                time.sleep(6)
                logger.debug(
                    "Autoscan : skip round because too many running tools ")
                check = getAutoScanStatus(pentest)
                continue
            if autoqueue:
                tools_lauchable = findLaunchableTools(pentest)
                queueTasks(pentest, [tool_model["tool"].getId()
                        for tool_model in tools_lauchable])
            launchableTools = []
            queue = dbclient.findInDb(pentest, "autoscan", {
                                      "type": "queue"}, False)
            autoscan_state = dbclient.findInDb(
                pentest, "autoscan", {"special": True}, False)
            if autoscan_state is None:
                continue
            authorized_commands = autoscan_state["authorized_commands"]
            if queue is None:
                launchableTools = []
            else:
                launchableTools = queue["tools"]
            logger.debug("Autoscan : launchable tools: " +
                         str(len(launchableTools)))
            # launchableTools.sort(key=lambda tup: (int(tup["timedout"]), int(tup["priority"])))
            toLaunch = []

            for launchableTool in launchableTools:
                priority = launchableTool["priority"]
                launchableToolIid = launchableTool["iid"]
                check = getAutoScanStatus(pentest)
                if not check:
                    break
                if autoscan_threads - len(toLaunch) - running_tools_count <= 0:
                    break
                logger.debug("Autoscan : launch task tools: " +
                             str(launchableToolIid))
                msg, statuscode = isLaunchable(
                    pentest, launchableToolIid, authorized_commands)
                if statuscode == 404:
                    dbclient.updateInDb(pentest, "autoscan", {"type": "queue"}, {
                                        "$pull": {"tools": {"iid": launchableToolIid}}})
                    tool_o = ServerTool.fetchObject(
                        pentest, {"_id": ObjectId(launchableToolIid)})
                    if tool_o is not None:
                        tool_o.markAsError(msg)
                elif statuscode == 403:
                    dbclient.updateInDb(pentest, "autoscan", {"type": "queue"}, {
                                        "$pull": {"tools": {"iid": launchableToolIid}}})
                elif statuscode == 200:
                    dbclient.updateInDb(pentest, "autoscan", {"type": "queue"}, {
                                        "$pull": {"tools": {"iid": launchableToolIid}}})
                    toLaunch.append([launchableToolIid, msg])
                    # the tool will be launched, we can remove it from the queue, let the worker set it as running
            for tool in toLaunch:
                launchTask(pentest, tool[0], tool[1], endoded_token)
            check = getAutoScanStatus(pentest)
            time.sleep(6)
    except (KeyboardInterrupt, SystemExit):
        logger.debug(
            "Autoscan : EXIT by expected EXCEPTION (exit or interrupt)")
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
    workers = dbclient.getWorkers({"pentest": pentest})
    for worker in workers:
        tools = dbclient.findInDb(
            pentest, "tools", {"scanner_ip": worker["name"], "status": "running"}, True)
        for tool in tools:
            toolsRunning.append(tool["_id"])
    dbclient.deleteFromDb(pentest, "autoscan", {}, True)
    for toolId in toolsRunning:
        res, msg = stopTask(pentest, toolId, {"forceReset": True})
    return "Success"


@permission("pentester")
def getAutoScanStatus(pentest):
    # commandsRunning = dbclient.aggregate("tools", [{"$match": {"datef": "None", "dated": {
    #        "$ne": "None"}, "scanner_ip": {"$ne": "None"}}}, {"$group": {"_id": "$name", "count": {"$sum": 1}}}])
    dbclient = DBClient.getInstance()
    return dbclient.findInDb(pentest, "autoscan", {"special": True}, False) is not None


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
    autoscan_enr = dbclient.findInDb(
        pentest, "autoscan", {"special": True}, False)
    if autoscan_enr is None:
        return toolsLaunchable
    authorized_commands = [ObjectId(x)
                           for x in autoscan_enr["authorized_commands"]]
    pentest_commands = ServerCommand.fetchObjects(
        {"_id": {"$in": authorized_commands}}, pentest)
    authorized_original_commands = [
        str(x.original_iid) for x in pentest_commands]
    check_items = list(CheckItem.fetchObjects(
        {"check_type": "auto_commands", "commands": {"$in": authorized_original_commands}}))
    check_items.sort(key=lambda c: c.priority)
    # get not done tools inside wave
    for check_item in check_items:
        check_instances = CheckInstance.fetchObjects(
            pentest, {"check_iid": str(check_item._id), "status": {"$ne": "done"}})
        check_ids = [str(x._id) for x in check_instances]
        tools_without_ip = ServerTool.fetchObjects(pentest, {"check_iid": {
                                                   "$in": check_ids}, "ip": "", "dated": "None", "datef": "None"})
        ips_in_scopes = ServerIp.fetchObjects(
            pentest, {"in_scopes": {"$ne": []}})
        ips_in_scopes = [x.ip for x in ips_in_scopes]
        tools_with_ip_in_scope = ServerTool.fetchObjects(pentest, {"check_iid": {
                                                         "$in": check_ids}, "ip": {"$in": ips_in_scopes}, "dated": "None", "datef": "None"})
        for tool in chain(tools_without_ip, tools_with_ip_in_scope):
            if "error" in tool.status:
                continue
            toolsLaunchable.append(
                {"tool": tool, "name": str(tool), "priority": int(check_item.priority), "timedout": "timedout" in tool.status})
        # for check_instance in check_instances:
        #     notDoneToolsInCheck = getNotDoneToolsPerScope(pentest, check_instance, authorized_commands)
        #     for toolId, toolModel in notDoneToolsInCheck.items():
        #         if "error" in toolModel.status:
        #             continue
        #         toolsLaunchable.append(
        #             {"tool": toolModel, "name": str(toolModel), "priority":int(check_item.priority), "timedout":"timedout" in toolModel.status})
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

# def getNotDoneToolsPerScope(pentest, check_instance, authorized_commands):
#     """Returns a set of tool mongo ID that are not done yet.
#     """
#     #
#     notDoneTools = dict()
#     # get not done tools that are not IP based (scope)
#     tools = ServerTool.fetchObjects(pentest, {"check_iid":str(check_instance._id), "command_iid":{ "$in": authorized_commands }, "ip":"", "dated": "None", "datef": "None"})
#     for tool in tools:
#         notDoneTools[tool.getId()] = tool
#     # fetch scopes to get IPs in scope
#     scopes = ServerScope.fetchObjects(pentest, {})
#     for scope in scopes:
#         scopeId = scope.getId()
#         # get IPs in scope
#         ips = ServerIp.getIpsInScope(pentest, scopeId)
#         for ip in ips:
#             # fetch IP level and below (e.g port) tools
#             tools = ServerTool.fetchObjects(pentest, {"check_iid":str(check_instance._id), "command_iid":{ "$in": authorized_commands }, "ip": ip.ip, "dated": "None", "datef": "None"})
#             for tool in tools:
#                 notDoneTools[tool.getId()] = tool
#     return notDoneTools
