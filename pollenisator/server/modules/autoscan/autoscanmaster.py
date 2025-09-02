"""Module for orchestrating an automatic scan. Must be run in a separate thread/process."""
import time
from itertools import chain
from threading import Thread
from datetime import datetime
import traceback
from typing import Any, Dict, List, Literal, Optional, Set, Tuple, cast
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
    authorized_commands = body.get("command_iids", None)
    autoqueue = body.get("autoqueue", False)
    if authorized_commands is not None:
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
    dbclient.send_notify(pentest, "autoscan", "", "start")
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

def try_start_tool(pentest: str, launchableTool: Dict[str, Any], authorized_commands: Optional[List[str]], toLaunch: List[Tuple[ObjectId, str]]) -> None:
    """
    Try to start a tool if it is launchable.
    Args:
        pentest (str): The name of the current pentest.
        launchableTool (Dict[str, Any]): The tool to launch.
        authorized_commands (Optional[List[str]]): The list of authorized commands.
        toLaunch (List[Tuple[ObjectId, str]]): The list of tools to launch.
    Raises:
        ValueError: If the tool is not found in the database.
    Returns:
        None
    """
    dbclient = DBClient.getInstance()
    force = launchableTool.get("force", False)
    launchableToolIid = launchableTool["iid"]
    logger.debug("Autoscan : launch task tools: %s", str(launchableToolIid))
    tool_o = Tool.fetchObject(
        pentest, {"_id": ObjectId(launchableToolIid)})
    if tool_o is None:
        raise ValueError("Tool not found in db")
    tool_o = cast(Tool, tool_o)
    msg, statuscode = tool_o.isLaunchable(authorized_commands, force)
    if statuscode == 404:
        logger.debug("Autoscan : tool %s not found in db", str(launchableToolIid))
        # tool not found in db, remove it from queue
        dbclient.updateInDb(pentest, "autoscan", {"type": "queue"}, {
                            "$pull": {"tools": {"iid": launchableToolIid}}}, notify=False)
        dbclient.send_notify(pentest, "queue", launchableToolIid, "delete")
    elif statuscode == 400:
        tool_o = Tool.fetchObject(
            pentest, {"_id": ObjectId(launchableToolIid)})
        if tool_o is not None:
            tool_o = cast(Tool, tool_o)
            tool_o.markAsError(msg)
    elif statuscode == 403:
        logger.debug("Autoscan : tool %s not launchable: %s", str(launchableToolIid), msg)
        # tool not launchable, remove it from queue
        dbclient.updateInDb(pentest, "autoscan", {"type": "queue"}, {
                            "$pull": {"tools": {"iid": launchableToolIid}}}, notify=False)
        dbclient.send_notify(pentest, "queue", launchableToolIid, "delete")
    elif statuscode == 200:
        logger.debug("Autoscan : tool %s launchable: %s", str(launchableToolIid), msg)
        dbclient.updateInDb(pentest, "autoscan", {"type": "queue"}, {
                            "$pull": {"tools": {"iid": launchableToolIid}}}, notify=False)
        dbclient.send_notify(pentest, "queue", launchableToolIid, "delete")
        toLaunch.append((launchableToolIid, msg))
        # the tool will be launched, we can remove it from the queue, let the worker set it as running

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
            logger.debug("Autoscan :autoqueue: %s", str(autoqueue))
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
            launchableTools = [] if queue is None else queue.get("tools", [])
            logger.debug("Autoscan : launchable tools: %s", str(len(launchableTools)))
            # launchableTools.sort(key=lambda tup: (int(tup["timedout"]), int(tup["priority"])))
            toLaunch: List[Tuple[ObjectId, str]] = []
            for launchableTool in launchableTools:
                #priority = launchableTool["priority"]
                check = getAutoScanStatus(pentest)
                if not check:
                    break
                if autoscan_threads - len(toLaunch) - running_tools_count <= 0:
                    break
                try:
                    try_start_tool(pentest, launchableTool, authorized_commands, toLaunch)
                except ValueError:
                    continue # tool not found in db
            for tool in toLaunch:
                dbclient.send_notify(pentest, "running_tools", tool[0], "insert")
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
    dbclient.send_notify(pentest, "autoscan", "", "stop")
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
    dbclient = DBClient.getInstance()

    time_compatible_waves_id = searchForAddressCompatibleWithTime(pentest)
    if time_compatible_waves_id is None:
        logger.debug("No wave compatible with time found")
        return toolsLaunchable
    autoscan_enr = dbclient.findInDb(pentest, "autoscan", {"special": True}, False)
    if autoscan_enr is None:
        logger.debug("No autoscan is running")
        return toolsLaunchable
    if autoscan_enr["authorized_commands"] is None:
        logger.debug("No authorized commands found in autoscan")
        return toolsLaunchable
    authorized_commands = [ObjectId(x) for x in autoscan_enr["authorized_commands"]]
    pentest_commands = Command.fetchObjects(pentest, {"_id": {"$in": authorized_commands}})
    authorized_original_commands = [ObjectId(x.original_iid) for x in pentest_commands]
    check_items = list(CheckItem.fetchObjects("pollenisator", {"check_type": "auto_commands", "commands": {"$in": authorized_original_commands}}))
    check_items.sort(key=lambda c: c.priority)
    # get not done tools inside wave
    for check_item in check_items:
        toolsLaunchable += find_launchable_tools_per_checkitem(pentest, check_item)
    return toolsLaunchable

def find_launchable_tools_per_checkitem(pentest:str , check_item: CheckItem) -> List[LaunchableToolType]:
    """
    Find launchable tools for a given check item.
    Args:
        pentest (str): The name of the current pentest.
        check_item (CheckItem): The check item to find launchable tools for.
    Returns:
        List[LaunchableToolType]: A list of launchable tools.
    """
    toolsLaunchable: List[LaunchableToolType] = []
    check_instances = CheckInstance.fetchObjects(
            pentest, {"check_iid": ObjectId(check_item.getId()), "status": {"$ne": "done"}})
    check_ids = [ObjectId(x.getId()) for x in check_instances]
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
