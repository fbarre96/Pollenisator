"""Module for orchestrating an automatic scan. Must be run in a separate thread/process."""
import time
from itertools import chain
from threading import Thread
from datetime import datetime
import traceback
from typing import Any, Dict, List, Literal, Set, Tuple, cast
from typing_extensions import TypedDict
from bson.objectid import ObjectId
from bson.errors import InvalidId
import pollenisator.core.components.utils as utils
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.models.command import Command
from pollenisator.core.models.element import Element
from pollenisator.core.models.interval import Interval
from pollenisator.core.models.ip import Ip
from pollenisator.core.models.tool import Tool
from pollenisator.server.modules.cheatsheet.checkinstance import CheckInstance
from pollenisator.server.modules.cheatsheet.cheatsheet import CheckItem
from pollenisator.server.permission import permission
from pollenisator.server.token import encode_token
from pollenisator.core.components.logger_config import logger

LaunchableToolType = TypedDict('LaunchableToolType', {'tool': Tool, 'name': str, 'priority': int, 'timedout': bool})

@permission("pentester")
def startAutoScan(pentest: str, body: Dict[str, Any], **kwargs: Any) -> Tuple[str, int]:
    """
    Start an automatic scan.

    Args:
        pentest (str): The name of the current pentest.
        body (Dict[str, Any]): The body of the request containing the command ids and the autoqueue flag.
        **kwargs (Any): Additional keyword arguments.

    Returns:
        Tuple[str, int]: The result of the start operation.
    """
    dbclient = DBClient.getInstance()
    authorized_commands = body.get("command_iids", [])
    autoqueue = body.get("autoqueue", False)
    for authorized_command in authorized_commands:
        try:
            _ = ObjectId(authorized_command) # test Object id valid
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
    Tool.queueTasks(pentest, set([tool_model["tool"].getId() for tool_model in tools_lauchable]))
    autoscan = Thread(target=autoScan, args=(pentest, encoded, autoqueue))
    try:
        logger.debug("Autoscan : start")
        autoscan.start()
    except (KeyboardInterrupt, SystemExit):
        dbclient.deleteFromDb(pentest, "autoscan", {}, True)
    return "Success", 200


def autoScan(pentest: str, endoded_token: str, autoqueue: bool) -> None:
    """
    Search tools to launch within defined conditions and attempts to launch them this worker.
    Gives a visual feedback on stdout.

    Args:
        pentest (str): The database to search tools in.
        endoded_token (str): The encoded token.
        autoqueue (bool): The autoqueue flag.
    """
    dbclient = DBClient.getInstance()
    check = True
    try:
        while check:
            autoscan_threads_settings = dbclient.findInDb(
                pentest, "settings", {"key": "autoscan_threads"}, False)
            autoscan_threads = 4 if autoscan_threads_settings is None else int(autoscan_threads_settings["value"])

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
                logger.debug("Queing tasks %s",str(len(tools_lauchable)))
                Tool.queueTasks(pentest, set([tool_model["tool"].getId() for tool_model in tools_lauchable]))
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
            logger.debug("Autoscan : launchable tools: %s", str(len(launchableTools)))
            # launchableTools.sort(key=lambda tup: (int(tup["timedout"]), int(tup["priority"])))
            toLaunch: List[Tuple[ObjectId, str]] = []

            for launchableTool in launchableTools:
                #priority = launchableTool["priority"]
                force = launchableTool.get("force", False)
                launchableToolIid = launchableTool["iid"]
                check = getAutoScanStatus(pentest)
                if not check:
                    break
                if autoscan_threads - len(toLaunch) - running_tools_count <= 0:
                    break
                logger.debug("Autoscan : launch task tools: %s", str(launchableToolIid))
                tool_o = Tool.fetchObject(
                    pentest, {"_id": ObjectId(launchableToolIid)})
                if tool_o is None:
                    continue
                tool_o = cast(Tool, tool_o)
                msg, statuscode = tool_o.isLaunchable(authorized_commands, force)
                if statuscode == 404:
                    dbclient.updateInDb(pentest, "autoscan", {"type": "queue"}, {
                                        "$pull": {"tools": {"iid": launchableToolIid}}})
                    tool_o = Tool.fetchObject(
                        pentest, {"_id": ObjectId(launchableToolIid)})
                    if tool_o is not None:
                        tool_o = cast(Tool, tool_o)
                        tool_o.markAsError(msg)
                elif statuscode == 403:
                    dbclient.updateInDb(pentest, "autoscan", {"type": "queue"}, {
                                        "$pull": {"tools": {"iid": launchableToolIid}}})
                elif statuscode == 200:
                    dbclient.updateInDb(pentest, "autoscan", {"type": "queue"}, {
                                        "$pull": {"tools": {"iid": launchableToolIid}}})
                    toLaunch.append((launchableToolIid, msg))
                    # the tool will be launched, we can remove it from the queue, let the worker set it as running
            for tool in toLaunch:
                Tool.launchTask(pentest, tool[0], tool[1], endoded_token)
            check = getAutoScanStatus(pentest)
            time.sleep(6)
    except (KeyboardInterrupt, SystemExit):
        logger.debug(
            "Autoscan : EXIT by expected EXCEPTION (exit or interrupt)")
        logger.info("stop autoscan : Kill received...")
        dbclient.deleteFromDb(pentest, "autoscan", {}, True)
    except Exception as e:
        tb = traceback.format_exc()
        print(tb)
        logger.exception(e)
        logger.debug("autoscan : %s", tb)
        logger.error(str(e))


@permission("pentester")
def stopAutoScan(pentest: str) -> Literal["Success"]:
    """
    Stop the automatic scan.

    Args:
        pentest (str): The name of the current pentest.

    Returns:
        str: Success
    """
    logger.debug("Autoscan : stop autoscan received ")
    dbclient = DBClient.getInstance()
    toolsRunning: List[Tool] = []
    workers = dbclient.getWorkers({"pentest": pentest})
    if workers is not None:
        for worker in workers:
            tools = Tool.fetchObjects(pentest, {"scanner_ip": worker["name"], "status": "running"})
            if tools is not None:
                for tool in tools:
                    toolsRunning.append(cast(Tool, tool))
    dbclient.deleteFromDb(pentest, "autoscan", {}, True)
    for tool_o in toolsRunning:
        tool_o = cast(Tool, tool_o)
        _res, _msg = tool_o.stopTask(forceReset=True)
    return "Success"


@permission("pentester")
def getAutoScanStatus(pentest: str) -> bool:
    """
    Get the status of the automatic scan.

    Args:
        pentest (str): The name of the current pentest.

    Returns:
        bool: True if the automatic scan is running, False otherwise.
    """
    dbclient = DBClient.getInstance()
    return dbclient.findInDb(pentest, "autoscan", {"special": True}, False) is not None


def findLaunchableTools(pentest: str) -> List[LaunchableToolType]:
    """ 
    Try to find tools that matches all criteria.

    Args:
        pentest (str): The name of the current pentest.

    Returns:
        List[Dict[str, Union[Tool, str, int, bool]]]: A list of launchable tools as dictionary with values _id, name and priority.
    """
    toolsLaunchable: List[LaunchableToolType] = []
    time_compatible_waves_id = searchForAddressCompatibleWithTime(pentest)
    if time_compatible_waves_id is None:
        logger.debug("No wave compatible with time found")
        return toolsLaunchable
    dbclient = DBClient.getInstance()
    autoscan_enr = dbclient.findInDb(
        pentest, "autoscan", {"special": True}, False)
    if autoscan_enr is None:
        logger.debug("No autoscan is running")
        return toolsLaunchable
    authorized_commands = [ObjectId(x)
                           for x in autoscan_enr["authorized_commands"]]
    pentest_commands = Command.fetchObjects(pentest, {"_id": {"$in": authorized_commands}})
    authorized_original_commands = [
        str(x.original_iid) for x in pentest_commands]
    check_items = list(CheckItem.fetchObjects("pollenisator",
        {"check_type": "auto_commands", "commands": {"$in": authorized_original_commands}}))
    check_items.sort(key=lambda c: c.priority)
    # get not done tools inside wave
    for check_item in check_items:
        check_instances = CheckInstance.fetchObjects(
            pentest, {"check_iid": str(check_item.getId()), "status": {"$ne": "done"}})
        check_ids = [str(x.getId()) for x in check_instances]
        tools_without_ip_db = Tool.fetchObjects(pentest, {"check_iid": {
                                                   "$in": check_ids}, "ip": "", "dated": "None", "datef": "None"})
        ips_in_scopes_db = Ip.fetchObjects(
            pentest, {"in_scopes": {"$ne": []}})
        if ips_in_scopes_db is None:
            ips_in_scopes = []
        else:
            ips_in_scopes = [cast(Ip, x).ip for x in ips_in_scopes_db]
        tools_with_ip_in_scope_db = Tool.fetchObjects(pentest, {"check_iid": {
                                                         "$in": check_ids}, "ip": {"$in": ips_in_scopes}, "dated": "None", "datef": "None"})
        if tools_without_ip_db is None:
            tools_without_ip: List[Element] = []
        else:
            tools_without_ip = list(tools_without_ip_db)
        if tools_with_ip_in_scope_db is None:
            tools_with_ip_in_scope: List[Element] = []
        else:
            tools_with_ip_in_scope = list(tools_with_ip_in_scope_db)

        for tool in chain(tools_without_ip, tools_with_ip_in_scope):
            tool = cast(Tool, tool)
            if "error" in tool.status:
                continue
            toolsLaunchable.append(
                {"tool": tool, "name": str(tool), "priority": int(check_item.priority), "timedout": "timedout" in tool.status})
    return toolsLaunchable


def searchForAddressCompatibleWithTime(pentest: str) -> Set[str]:
    """
    Return a list of wave which have at least one interval fitting the actual time.

    Args:
        pentest (str): The name of the current pentest.

    Returns:
        Set[str]: A set of wave names.
    """
    waves_to_launch: Set[str] = set()
    intervals = Interval.fetchObjects(pentest, {})
    if intervals is None:
        return waves_to_launch
    for intervalModel in intervals:
        intervalModel = cast(Interval, intervalModel)
        if utils.fitNowTime(intervalModel.dated, intervalModel.datef):
            waves_to_launch.add(intervalModel.wave)
    return waves_to_launch
