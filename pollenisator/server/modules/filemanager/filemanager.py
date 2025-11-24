"""
Module to manage files upload and download.
"""
import json
import os
from flask import after_this_request
import tempfile
import time
import traceback
import hashlib
import zipfile
import pathlib
from datetime import datetime
from typing import IO, Dict, List, Literal, Optional, Tuple, Union, Any, cast
from typing_extensions import TypedDict
from bson import ObjectId
import bson
from flask import Response, send_file
import werkzeug
from pollenisator.core.components.logger_config import logger
from pollenisator.core.components.tag import Tag
from pollenisator.core.components.utils import loadPlugin, detectPlugins
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.components.utils import getMainDir
from pollenisator.core.models.defect import Defect
from pollenisator.core.models.tool import Tool
from pollenisator.server.modules.cheatsheet.checkinstance import getTargetRepr
from pollenisator.server.permission import permission
from pollenisator.core.components.socketmanager import SocketManager
from enum import Enum
import uuid
try:
    import eventlet
    HAS_EVENTLET = True
    logger.info("filemanager module: eventlet is available, async imports will use green threads")
except ImportError:
    HAS_EVENTLET = False
    logger.warning("filemanager module: eventlet NOT available, async imports will run synchronously")

class FileType(str, Enum):
    PROOF = "proof"
    RESULT = "result"
    FILE = "file"

POSSIBLE_TYPES = [ft.value for ft in FileType]

# Import task tracking for async operations
ImportTaskStatus = TypedDict('ImportTaskStatus', {
    'task_id': str, 
    'status': str, 
    'results': Optional[Dict[str, int]], 
    'error': Optional[str], 
    'created_at': float, 
    'updated_at': float
})

# Global in-memory task storage
# NOTE: This is shared within a single process/worker. If running with multiple 
# gunicorn workers, each worker will have its own dictionary. For multi-worker 
# deployments, consider using Redis or the database for task storage.
# With eventlet (default), this works correctly as all green threads share memory.
IMPORT_TASKS: Dict[str, ImportTaskStatus] = {}
IMPORT_TASKS_CLEANUP_TIME = 3600  # Clean up completed tasks older than 1 hour

# For thread safety in debug/threading mode
try:
    import threading
    IMPORT_TASKS_LOCK = threading.RLock()
    HAS_THREADING = True
except ImportError:
    IMPORT_TASKS_LOCK = None  # type: ignore
    HAS_THREADING = False

dbclient = DBClient.getInstance()
local_path = os.path.normpath(os.path.join(getMainDir(), "files"))
try:
    os.makedirs(local_path)
except FileExistsError:
    pass

ErrorStatus = Tuple[str, int]
FileUploadResult = TypedDict('FileUploadResult', {'remote_path': str, 'msg': str, 'attachment_id':str, 'status': int})

def none_or_str(value: Any) -> Union[str, None]:
    """
    Return the value if it is a string, otherwise None.

    Args:
        value (Any): The value to check.

    Returns:
        Union[str, None]: The value if it is a string, otherwise None.
    """
    if value is None:
        return None
    return str(value)

def is_valid_object_id(value: Union[str, ObjectId]) -> bool:
    try:
        ObjectId(value)
    except bson.errors.InvalidId:
        return False
    return True

def md5(f: IO[bytes]) -> str:
    """
    Compute md5 hash of the given file stream.

    Args:
        fname (IO[bytes]): open file you want to compute the md5 of.

    Returns:
        str: The digested hash of the file in an hexadecimal string format.

    """
    hash_md5 = hashlib.md5()
    for chunk in iter(lambda: f.read(4096), b""):
        hash_md5.update(chunk)
    return hash_md5.hexdigest()

def _get_task(task_id: str) -> Optional[ImportTaskStatus]:
    """Thread-safe task retrieval."""
    if HAS_THREADING and IMPORT_TASKS_LOCK:
        with IMPORT_TASKS_LOCK:
            return IMPORT_TASKS.get(task_id)
    return IMPORT_TASKS.get(task_id)

def _set_task(task_id: str, task_data: ImportTaskStatus) -> None:
    """Thread-safe task storage."""
    if HAS_THREADING and IMPORT_TASKS_LOCK:
        with IMPORT_TASKS_LOCK:
            IMPORT_TASKS[task_id] = task_data
    else:
        IMPORT_TASKS[task_id] = task_data

def _update_task_status(task_id: str, status: str, **kwargs: Any) -> None:
    """Thread-safe task status update."""
    if HAS_THREADING and IMPORT_TASKS_LOCK:
        with IMPORT_TASKS_LOCK:
            if task_id in IMPORT_TASKS:
                IMPORT_TASKS[task_id]['status'] = status
                IMPORT_TASKS[task_id]['updated_at'] = time.time()
                for key, value in kwargs.items():
                    IMPORT_TASKS[task_id][key] = value  # type: ignore
    else:
        if task_id in IMPORT_TASKS:
            IMPORT_TASKS[task_id]['status'] = status
            IMPORT_TASKS[task_id]['updated_at'] = time.time()
            for key, value in kwargs.items():
                IMPORT_TASKS[task_id][key] = value  # type: ignore

def _cleanup_old_import_tasks() -> None:
    """
    Clean up completed import tasks older than IMPORT_TASKS_CLEANUP_TIME.
    This is called periodically to prevent memory leaks from accumulating task data.
    Thread-safe implementation.
    """
    current_time = time.time()
    tasks_to_remove = []
    
    if HAS_THREADING and IMPORT_TASKS_LOCK:
        with IMPORT_TASKS_LOCK:
            for task_id, task_info in IMPORT_TASKS.items():
                if current_time - task_info['updated_at'] > IMPORT_TASKS_CLEANUP_TIME:
                    tasks_to_remove.append(task_id)
            for task_id in tasks_to_remove:
                del IMPORT_TASKS[task_id]
                logger.info("Cleaned up old import task: %s", task_id)
    else:
        for task_id, task_info in IMPORT_TASKS.items():
            if current_time - task_info['updated_at'] > IMPORT_TASKS_CLEANUP_TIME:
                tasks_to_remove.append(task_id)
        for task_id in tasks_to_remove:
            del IMPORT_TASKS[task_id]
            logger.info("Cleaned up old import task: %s", task_id)

def _execute_import_task_async(task_id: str, pentest: str, upfile_data: Tuple[bytes, str], body: Dict[str, Any], user: str) -> None:
    """
    Execute the import task asynchronously in a background thread.
    This function processes the file import in the background to avoid blocking the HTTP request.
    
    Args:
        task_id (str): The unique task ID for tracking.
        pentest (str): The pentest name.
        upfile_data (Tuple[bytes, str]): Tuple of (file content bytes, filename).
        body (Dict[str, Any]): The request body with plugin, default_target, cmdline.
        user (str): The user performing the import.
    """
    try:
        logger.info("=== ASYNC TASK STARTED === Import task %s for pentest %s by user %s", task_id, pentest, user)
        _update_task_status(task_id, 'processing')
        logger.info("Task %s status updated to 'processing'", task_id)
        # Create a file-like object from the data
        from io import BytesIO
        file_content, filename = upfile_data
        file_stream = BytesIO(file_content)
        
        # Parse and validate parameters
        parse_result = _parse_import_parameters(body)
        if isinstance(parse_result, tuple) and len(parse_result) == 2:
            error_msg, _ = parse_result
            _update_task_status(task_id, 'failed', error=error_msg)
            logger.warning("Import task %s failed: %s", task_id, error_msg)
            return
        
        plugin, default_target, cmdline = cast(Tuple[str, Dict[str, Any], str], parse_result)
        
        # Prepare file information
        md5_file = md5(file_stream)
        file_stream.seek(0)
        name = DBClient.sanitize_filename(filename) if filename is not None else "file_"+str(time.time()).replace(".", "_")
        tool_name = os.path.splitext(os.path.basename(name))[0] + md5_file[:6]
        ext = os.path.splitext(name)[-1]
        
        # Create a mock file object for compatibility with existing functions
        class MockFileStorage:
            def __init__(self, stream: IO[bytes], filename: Optional[str]):
                self.stream = stream
                self.filename = filename
        
        mock_file = MockFileStorage(file_stream, filename)
        
        # Process plugins
        plugin_results, results_count, error_msg_optional = _process_plugin_results(pentest, mock_file, plugin, cmdline, ext)  # type: ignore
        
        if error_msg_optional:
            _update_task_status(task_id, 'failed', error=error_msg_optional)
            logger.warning("Import task %s failed during plugin processing: %s", task_id, error_msg_optional)
            return
        
        # Process each plugin result
        for result in plugin_results:
            file_stream.seek(0)  # Reset stream for each result
            _process_plugin_result(pentest, result, default_target, tool_name, user, mock_file, plugin)  # type: ignore
        
        _update_task_status(task_id, 'completed', results=results_count)
        logger.info("Import task %s completed successfully with results: %s", task_id, results_count)
        
    except Exception as e:  # pylint: disable=broad-except
        logger.error("Import task %s failed with exception: %s", task_id, str(e))
        logger.error(traceback.format_exc())
        _update_task_status(task_id, 'failed', error=f"Internal error: {str(e)}")

@permission("pentester")
def upload_replace(pentest: str, attachment_id: str, filetype: FileType, attached_to: Union[Literal["unassigned"]|str], upfile: werkzeug.datastructures.FileStorage) -> Union[FileUploadResult, ErrorStatus]:
    """
    Upload a file as proof for a defect.

    Args:
        pentest (str): The name of the pentest.
        attachment_id (str): The id of the attachment to replace.
        filetype (FileType): The type of the file to upload. (proof, file or result)
        attached_to (Union[Literal["unassigned"], str]): The id of the item the file is attached to.
        upfile (werkzeug.datastructures.FileStorage): The file to upload.

    Returns:
        Union[FileUploadResult, ErrorStatus]: A dictionary containing the remote path, message, and status if the upload was successful, otherwise a tuple containing the message and status.
    """
    result, status, filepath = dbclient.do_upload(pentest, attachment_id, filetype, upfile, attached_to)
    if status == 200:
        name = os.path.basename(filepath)
        return {"remote_path": f"files/{pentest}/download/{filetype}/{attached_to}/{name}", "attachment_id": str(result.get("attachment_id", "")), "msg":str(result.get("msg","")), "status":status}
    return str(result.get("msg","")), status


@permission("pentester")
def upload(pentest: str, attached_to: Union[Literal["unassigned"], str], filetype: FileType, upfile: werkzeug.datastructures.FileStorage) -> Union[FileUploadResult, ErrorStatus]:
    """
    Upload a file as proof for a defect.

    Args:
        pentest (str): The name of the pentest.
        attached_to (Union[Literal["unassigned"], str]): An id of a defect to link the file with (deletion of the defect will delete the file).
        filetype (FileType): The type of the file to upload. (proof, file or result)
        upfile (werkzeug.datastructures.FileStorage): The file to upload.

    Returns:
        Union[FileUploadResult, ErrorStatus]: A dictionary containing the remote path, message, and status if the upload was successful, otherwise a tuple containing the message and status.
    """
    result, status, filepath = dbclient.do_upload(pentest, "unassigned", filetype, upfile, attached_to)
    if status == 200:
        name = os.path.basename(filepath)
        return {"remote_path": f"files/{pentest}/download/{filetype}/{attached_to}/{name}", "attachment_id": str(result.get("attachment_id","")), "msg":str(result.get("msg","")), "status":status}
    return str(result.get("msg","")), status

@permission("user")
def upload_template_file(attached_to: Union[Literal["unassigned"], str], filetype: FileType, upfile: werkzeug.datastructures.FileStorage) -> Union[FileUploadResult, ErrorStatus]:
    """
    Upload a file as proof for a defect.

    Args:
        attached_to (Union[Literal["unassigned"], str]): An id of a defect to link the file with (deletion of the defect will delete the file).
        filetype (FileType): The type of the file to upload. (proof, file or result)
        upfile (werkzeug.datastructures.FileStorage): The file to upload.

    Returns:
        Union[FileUploadResult, ErrorStatus]: A dictionary containing the remote path, message, and status if the upload was successful, otherwise a tuple containing the message and status.
    """
    return upload("pollenisator", attached_to, filetype, upfile)

def _parse_import_parameters(body: Dict[str, Any]) -> Union[Tuple[str, Dict[str, Any], str], ErrorStatus]:
    """
    Parse and validate import parameters from the request body.
    
    Args:
        body (Dict[str, Any]): The request body containing import parameters.
        
    Returns:
        Union[Tuple[str, Dict[str, Any], str], ErrorStatus]: Either a tuple of (plugin, default_target, cmdline) 
        or an error message and status code.
    """
    plugin = body.get("plugin", "auto-detect")
    try:
        default_target = json.loads(body.get("default_target", {}))
    except json.JSONDecodeError:
        return "Invalid default_target", 400
    cmdline = body.get("cmdline", "")
    return plugin, default_target, cmdline

def _process_plugin_results(pentest: str, upfile: werkzeug.datastructures.FileStorage, plugin: str, 
                          cmdline: str, ext: str) -> Tuple[List[Dict[str, Any]], Dict[str, int], Optional[str]]:
    """
    Process plugin detection and parsing to get results.
    
    Args:
        pentest (str): The pentest name.
        upfile (werkzeug.datastructures.FileStorage): The uploaded file.
        plugin (str): The plugin to use or "auto-detect".
        cmdline (str): The command line.
        ext (str): The file extension.
        
    Returns:
        Tuple[List[Dict[str, Any]], Dict[str, int], Optional[str]]: Plugin results, results count, and any error message.
    """
    results_count: Dict[str, int] = {}
    plugin_results = []
    error_msg: Optional[str] = None
    
    if plugin == "auto-detect":
        # AUTO DETECT
        plugin_results = detectPlugins(pentest, upfile, cmdline, ext)
        for result in plugin_results:
            foundPlugin = result.get("plugin", None)
            if foundPlugin is not None:
                results_count[foundPlugin] = results_count.get(foundPlugin, 0) + 1
    else:
        # SET PLUGIN
        mod = loadPlugin(plugin)
        try:
            logger.info("PLUGIN for cmdline %s", str(cmdline))
            notes, tags, lvl, targets = mod.Parse(pentest, upfile.stream, cmdline=cmdline, ext=ext, filename=upfile.filename)
            results_count[plugin] = results_count.get(plugin, 0) + 1
            plugin_results.append({"plugin": plugin, "notes": notes, "tags": tags, "lvl": lvl, "targets": targets})
        except (ImportError, AttributeError, ValueError) as e:
            error_msg = str(e)
            logger.error("Plugin exception : %s", str(e))
            logger.error("Plugin exception : %s", traceback.format_exc())
            traceback.print_exc()
            
    return plugin_results, results_count, error_msg

def _prepare_notification_data(pentest: str, notes: str, tags: List[str], plugin: str, 
                             default_target: Dict[str, Any]) -> Dict[str, Any]:
    """
    Prepare notification data for default targets.
    
    Args:
        pentest (str): The pentest name.
        notes (str): The notes from plugin parsing.
        tags (List[str]): The tags from plugin parsing.
        plugin (str): The plugin name.
        default_target (Dict[str, Any]): The default target configuration.
        
    Returns:
        Dict[str, Any]: The notification data.
    """
    notif_data = {"notes": notes, "tags": tags, "plugin": plugin.replace(".py", "")}
    
    if default_target.get("check_iid", None) is not None:
        list_targets = default_target.get("check_iid", None)
        if not isinstance(list_targets, list):
            list_targets = [list_targets]
        result = getTargetRepr(pentest, list_targets)
        if result is None or not isinstance(result, dict) or len(result) == 0:
            notif_data["target_repr"] = "Unknown target"
        else:
            if len(list(result.values())) > 1:
                representations = ", ".join(list(result.values()))
                if len(representations) > 100:
                    representations = representations[:100] + "..."
                notif_data["target_repr"] = representations
                notif_data["target_iid"] = ", ".join([str(x) for x in list(result.keys())])
            else:
                notif_data["target_repr"] = list(result.values())[0]
                notif_data["target_iid"] = list(result.keys())[0]
                
    return notif_data

def _get_or_create_tools(pentest: str, target: Optional[Dict[str, Any]], tools_iids: List[ObjectId], 
                        toolName: str, check_iid: Optional[ObjectId], lvl: str, 
                        user: str, notes: str, date: str) -> List[Tool]:
    """
    Get existing tools or create new ones based on target configuration.
    
    Args:
        pentest (str): The pentest name.
        target (Optional[Dict[str, Any]]): The target configuration.
        tools_iids (List[ObjectId]): List of existing tool IDs.
        toolName (str): The tool name to create.
        check_iid (Optional[ObjectId]): The check instance ID.
        lvl (str): The level.
        user (str): The user.
        notes (str): The notes.
        date (str): The date.
        
    Returns:
        List[Tool]: List of tools and the tool ID.
    """
    tools_m: List[Tool] = []
    
    if tools_iids is not None and len(tools_iids) > 0:
        tools_results_m = Tool.fetchObjects(pentest, {"_id": {"$in": tools_iids}})
        if tools_results_m is not None:
            tools_m = [cast(Tool, tool_m) for tool_m in tools_results_m if tool_m is not None]
            for tool_m in tools_m:
                tool_m = cast(Tool, tool_m)
                tool_m.notes = notes
                tool_m.scanner_ip = user
                tool_iid = tool_m.getId()

    if len(tools_m) == 0:  # tool not found, create it
        if target is None:
            wave = scope = ip = port = proto = None
        else:
            wave = none_or_str(target.get("wave", None))
            scope = none_or_str(target.get("scope", None))
            ip = none_or_str(target.get("ip", None))
            port = none_or_str(target.get("port", None))
            proto = none_or_str(target.get("proto", None))
            
        tool_m = Tool(pentest).initialize(None, check_iid, wave, name=toolName,
                                        scope=scope, ip=ip, port=port, proto=proto,
                                        lvl=str(lvl), text="", text_multi="",
                                        dated=date, datef=date, scanner_ip=user,
                                        status=["done"], notes=notes)
        ret = tool_m.addInDb()
        tool_iid = ObjectId(ret["iid"])
        tool_m._id = tool_iid
        tools_m = [tool_m]
        
    return tools_m

def _finalize_tool_processing(pentest: str, tools_m: List[Tool], tags: List[str], 
                            upfile: werkzeug.datastructures.FileStorage, 
                            plugin: str) -> None:
    """
    Finalize tool processing by setting tags and uploading the file.
    
    Args:
        pentest (str): The pentest name.
        tools_m (List[Tool]): List of tools to process.
        tags (List[str]): Tags to set on tools.
        upfile (werkzeug.datastructures.FileStorage): The uploaded file.
        plugin (str): The plugin name.
    """
    db_client = DBClient.getInstance()
    if len(tools_m) > 0:
        for tool_m in tools_m:
            tag_objects = [Tag(tag) for tag in tags]
            tool_m.setTags(tag_objects)
            upfile.stream.seek(0)
            _res, status, filepath = db_client.do_upload(pentest, "unassigned", "result", upfile, str(tool_m.getId()), force_replace=True)
            if status == 200 or status == 409:
                tool_m.plugin_used = plugin
                # Use the protected method as intended by the original code
                tool_m._setStatus(["done"], filepath)  # type: ignore

def _process_plugin_result(pentest: str, result: Dict[str, Any], default_target: Dict[str, Any], 
                         toolName: str, user: str, upfile: werkzeug.datastructures.FileStorage, 
                         plugin: str) -> None:
    """
    Process a single plugin result by creating tools and handling notifications.
    
    Args:
        pentest (str): The pentest name.
        result (Dict[str, Any]): The plugin result.
        default_target (Dict[str, Any]): The default target configuration.
        toolName (str): The tool name.
        user (str): The user.
        upfile (werkzeug.datastructures.FileStorage): The uploaded file.
        plugin (str): The plugin name.
    """
    notes = result.get('notes')
    notes = "" if notes is None else notes
    tags = result.get('tags', [])
    tags = [] if tags is None else tags
    lvl = result.get('lvl', "imported")
    if lvl is None:  # because result["lvl"] = None is defined
        lvl = "imported"
    targets = result.get('targets', {})
    targets = {} if targets is None else targets
    
    notif_data = _prepare_notification_data(pentest, notes, tags, result.get("plugin", ""), default_target)
    
    if default_target:
        targets["default"] = default_target
        dbclient.send_notify(pentest, "checkinstances", str(default_target), "notif_terminal", data=notif_data)
        
    for tag in tags:
        tag = Tag(tag)
        dbclient.doRegisterTag(pentest, tag)

    # ADD THE RESULTING TOOL TO AFFECTED
    for target in targets.values():
        create_tool_for_target(pentest, toolName, user, upfile, plugin, notes, tags, lvl, target)

def create_tool_for_target(pentest, toolName, user, upfile, plugin, notes, tags, lvl, target):
    date = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    check_iid: Optional[ObjectId] = None
        
    if target is None:
        tools_iids: List[ObjectId] = []
    else:
        lvl = str(target.get("lvl", lvl))
        check_iid = target.get("check_iid", None)
        check_iids = []
        if not isinstance(check_iid, list):
            try:
                check_iid = None if target.get("check_iid", None) is None else ObjectId(target["check_iid"])
                check_iids.append(check_iid)
            except bson.errors.InvalidId:
                check_iid = None
        check_iids = [ObjectId(x) for x in check_iids if x is not None]
        tools_iids = target.get("tool_iid", [])
        if not isinstance(tools_iids, list):
            tools_iids = [tools_iids]
        tools_iids = [ObjectId(x) for x in tools_iids if is_valid_object_id(x)]
            
    tools_m = _get_or_create_tools(pentest, target, tools_iids, toolName, check_iid, 
                                               lvl, user, notes, date)
    _finalize_tool_processing(pentest, tools_m, tags, upfile, plugin)

@permission("pentester")
def importExistingFile(pentest: str, upfile: werkzeug.datastructures.FileStorage, body: Dict[str, Any], **kwargs: Dict[str, Any]) -> Union[str, Dict[str, int], ErrorStatus]:
    """
    Import an existing file into the pentest.

    Args:
        pentest (str): The name of the pentest.
        upfile (werkzeug.datastructures.FileStorage): The file to import.
        body (Dict[str, Any]): Additional parameters for the import, such as the plugin to use, the default target, and the command line.
        **kwargs (Dict[str, Any]): Additional keyword arguments, including the user token.

    Returns:
        Union[str, Dict[str, int]]: An error message if an error occurred, otherwise a dictionary mapping plugin names to the number of times they were used.
    """
    user = kwargs["token_info"]["sub"]
    
    # Parse and validate parameters
    parse_result = _parse_import_parameters(body)
    if isinstance(parse_result, tuple) and len(parse_result) == 2:
        error_msg, statuscode = parse_result
        return error_msg, statuscode  # Return just the error message
    plugin, default_target, cmdline = cast(Tuple[str, Dict[str, Any], str], parse_result)

    # Prepare file information
    md5File = md5(upfile.stream)
    upfile.stream.seek(0)
    name = DBClient.sanitize_filename(upfile.filename) if upfile.filename is not None else "file_"+str(time.time()).replace(".", "_")
    toolName = os.path.splitext(os.path.basename(name))[0] + md5File[:6]
    ext = os.path.splitext(name)[-1]
    
    # Process plugins
    plugin_results, results_count, error_msg_optional = _process_plugin_results(pentest, upfile, plugin, cmdline, ext)
    
    if error_msg_optional:
        return error_msg_optional
    
    # Process each plugin result
    for result in plugin_results:
        _process_plugin_result(pentest, result, default_target, toolName, user, upfile, plugin)
    
    return results_count

@permission("pentester")
def importExistingFileAsync(pentest: str, upfile: werkzeug.datastructures.FileStorage, body: Dict[str, Any], **kwargs: Dict[str, Any]) -> Union[Dict[str, str], ErrorStatus]:
    """
    Import an existing file into the pentest asynchronously.
    This endpoint queues the import task and returns immediately with a task ID.
    Use getImportTaskStatus to check the progress and getImportTaskResult to get the final result.

    Args:
        pentest (str): The name of the pentest.
        upfile (werkzeug.datastructures.FileStorage): The file to import.
        body (Dict[str, Any]): Additional parameters for the import, such as the plugin to use, the default target, and the command line.
        **kwargs (Dict[str, Any]): Additional keyword arguments, including the user token.

    Returns:
        Union[Dict[str, str], ErrorStatus]: A dictionary containing the task_id if the import was queued successfully, 
        otherwise an error message and status code.
    """
    user = kwargs["token_info"]["sub"]
    
    # Validate parameters early to fail fast
    parse_result = _parse_import_parameters(body)
    if isinstance(parse_result, tuple) and len(parse_result) == 2:
        error_msg, statuscode = parse_result
        return error_msg, statuscode
    
    try:
        # Read file content into memory
        file_content = upfile.stream.read()
        filename = upfile.filename if upfile.filename is not None else "file_"+str(time.time()).replace(".", "_")
        
        # Generate a unique task ID
        task_id = str(uuid.uuid4())
        
        # Initialize task tracking (thread-safe)
        current_time = time.time()
        task_data: ImportTaskStatus = {
            'task_id': task_id,
            'status': 'queued',
            'results': None,
            'error': None,
            'created_at': current_time,
            'updated_at': current_time
        }
        _set_task(task_id, task_data)
        
        # Cleanup old tasks periodically
        _cleanup_old_import_tasks()
        
        # Execute the import asynchronously using SocketIO's background task manager
        # This ensures the task runs in the proper eventlet/threading context
        sm = SocketManager.getInstance()
        logger.info("Spawning background import task %s for pentest %s using SocketIO", task_id, pentest)
        sm.socketio.start_background_task(
            _execute_import_task_async, 
            task_id, 
            pentest, 
            (file_content, filename), 
            body, 
            user
        )
        logger.info("Import task %s queued successfully", task_id)
        
        return {
            'task_id': task_id,
            'status': 'queued',
            'message': 'File import queued for processing'
        }
        
    except Exception as e:  # pylint: disable=broad-except
        logger.error("Error queueing import task: %s", str(e))
        logger.error(traceback.format_exc())
        return f"Error queueing file import: {str(e)}", 500

@permission("pentester")
def getImportTaskStatus(task_id: str) -> Union[ImportTaskStatus, ErrorStatus]:
    """
    Get the status of an import task.
    Returns the current state of the task including status, results (if completed), and error (if failed).

    Args:
        task_id (str): The ID of the import task returned from importExistingFileAsync.

    Returns:
        Union[ImportTaskStatus, ErrorStatus]: The task status if found, otherwise an error message and status code.
    """
    task_info = _get_task(task_id)
    if task_info is None:
        return "Task not found", 404
    
    return task_info

@permission("pentester")
def getImportTaskResult(task_id: str) -> Union[Dict[str, Any], Tuple[Dict[str, Any], int], ErrorStatus]:
    """
    Get the result of a completed import task.
    This endpoint returns the final result only if the task has completed.
    Returns HTTP 202 if still processing, HTTP 400 if failed.

    Args:
        task_id (str): The ID of the import task returned from importExistingFileAsync.

    Returns:
        Union[Dict[str, Any], Tuple[Dict[str, Any], int], ErrorStatus]: The task result if completed, 
        HTTP 202 if still processing, HTTP 400 if failed, or HTTP 404 if not found.
    """
    task_info = _get_task(task_id)
    if task_info is None:
        return "Task not found", 404
    
    if task_info['status'] == 'completed':
        return {
            'task_id': task_id,
            'status': 'completed',
            'results': task_info['results']
        }
    elif task_info['status'] == 'failed':
        return {
            'task_id': task_id,
            'status': 'failed',
            'error': task_info['error']
        }, 400
    else:
        # Task is still queued or processing
        return {
            'task_id': task_id,
            'status': task_info['status'],
            'message': 'Import is still processing'
        }, 202  # HTTP 202 Accepted - still processing

@permission("pentester")
def listFilesAll(pentest: str, filetype: FileType) -> Union[ErrorStatus, List[Dict[str, Any]]]:
    """
    List all files of a specific type in a pentest.

    Args:
        pentest (str): The name of the pentest.
        filetype (FileType): The type of the files to list. (proof, file or result)

    Returns:
       Union[ErrorStatus, List[Dict[str, Any]]]: A list of file documents if successful, otherwise an error message and status code.
    """
    if filetype not in POSSIBLE_TYPES:
        return "Invalid filetype", 400
    db_client = DBClient.getInstance()
    files = db_client.findInDb(pentest, "attachments", {"type": filetype}, multi=True)
    if files is None:
        return "No files found", 404
    files_dict = {file.get("filedigest",None): file for file in files if file is not None}
    if not files_dict:
        return "No files found", 404
    return list(files_dict.values())

def _list_proof_files(pentest: str, attached_to: ObjectId) -> List[str]:
    """
    List all proof files attached to a defect by its id.
    """
    defect = Defect.fetchObject(pentest, {"_id": attached_to})
    if defect is None:
        return []
    defect = cast(Defect, defect)
    try:
        return defect.listProofFiles()
    except FileNotFoundError:
        return []

def _list_result_files(pentest: str, attached_to: ObjectId) -> List[str]:
    tool = Tool.fetchObject(pentest, {"_id": attached_to})
    if tool is None:
        return []
    tool = cast(Tool, tool)
    return tool.listResultFiles()

def _list_file_files(pentest: str) -> List[str]:
    file_local_path = os.path.normpath(os.path.join(getMainDir(), "files"))
    filepath = os.path.join(file_local_path, pentest, "file", "unassigned")
    filepath = os.path.normpath(filepath)
    if not filepath.startswith(file_local_path):
        logger.error("Invalid path for listing files: %s", filepath)
        return [] # invalid path
    try:
        return os.listdir(filepath)
    except FileNotFoundError as e:
        logger.error("Error listing files: %s", str(e))
        return []
    

@permission("pentester")
def listFiles(pentest: str, attached_to: str, filetype: FileType) -> Union[ErrorStatus, List[str]]:
    """
    List all files of a specific type attached to a specific item in a pentest.

    Args:
        pentest (str): The name of the pentest.
        attached_iid (str): The id of the item the files are attached to.
        filetype (str): The type of the files to list.

    Returns:
       Union[ErrorStatus, List[str]]: A list of filenames if successful, otherwise an error message and status code.
    """
    if filetype not in POSSIBLE_TYPES:
        return "Invalid filetype", 400
    if not is_valid_object_id(attached_to) and attached_to != "unassigned":
        return "Invalid attached_iid", 400
    pentest = os.path.basename(pentest)
    try:
        if filetype == "proof":
            return _list_proof_files(pentest, ObjectId(attached_to))
        elif filetype == "result":
            return _list_result_files(pentest, ObjectId(attached_to))
        elif filetype == "file":
            return _list_file_files(pentest)
        else:
            return "Invalid filetype", 400
    except ValueError:
        return "Invalid path", 400
    except FileNotFoundError:
        return "File not found", 404
    return []

@permission("pentester")
def downloadById(pentest: str, attachment_id: str) -> Union[ErrorStatus, Response]:
    """
    Download a file by its attachment id.

    Args:
        pentest (str): The name of the pentest.
        attachment_id (str): The id of the attachment to download.

    Returns:
       Union[ErrorStatus, Response]: The file to download if successful, otherwise an error message and status code.
    """
    attachment = dbclient.findInDb(pentest, "attachments", {"attachment_id": attachment_id}, False)
    if attachment is None:
        return "Attachment not found", 404
    return download(pentest, attachment.get("attached_to", "unassigned"), attachment.get("type", "file"), attachment.get("name", None))

def _download_by_filename(filepath: str, filename: str) -> Union[ErrorStatus, Response]:
    filename = DBClient.sanitize_filename(filename)
    filepath = os.path.join(filepath, os.path.basename(filename))
    if os.path.exists(filepath):
        return send_file(filepath)
    else:
        filepath = os.path.join(local_path, "pollenisator", "file", "unassigned", os.path.basename(filename))
        filepath = os.path.normpath(filepath)
        if not filepath.startswith(local_path):
            return "Invalid path", 400
        if os.path.exists(filepath):
            return send_file(filepath)
    return "File not found", 404

def send_zip_file(filepath: str, attached_to: ObjectId) -> Response:
    # generate a temp zip file
    temp_zipfile_dir = tempfile.mkdtemp()
    temp_zipfile_path = os.path.join(temp_zipfile_dir, str(attached_to)+".zip")
    dir_source = pathlib.Path(filepath)
    @after_this_request
    def remove_file(response):
        try:
            os.remove(temp_zipfile_path)
        except (OSError, FileNotFoundError):
            pass
        return response
    with zipfile.ZipFile(temp_zipfile_path, mode="w") as archive:
        for file_path in dir_source.iterdir():
            archive.write(file_path, arcname=file_path.name)
    return send_file(temp_zipfile_path, mimetype="application/zip")

@permission("user")
def download_template_file(attached_to: str, filetype: FileType, filename: Optional[str]=None) -> Union[ErrorStatus, Response]:
    """ 
    Download a template file of a specific type attached to a specific item.

    Args:
        attached_to (str): The id of the item the file is attached to.
        filetype (str): The type of the file to download.
        filename (Optional[str], optional): The name of the file to download. Defaults to None. If not specified and multiple files are found, 
            the file will be zipped and the zip file will be downloaded. 
            If specified, the file will be downloaded directly.
    Returns:
        Union[ErrorStatus, Response]: The file to download if successful, otherwise an error message and status code.
    """ 
    return download("pollenisator", attached_to, filetype, filename)

@permission("pentester")
def download(pentest: str, attached_to: str, filetype: FileType, filename: Optional[str]=None) -> Union[ErrorStatus, Response]:
    """ 
    Download a file of a specific type attached to a specific item in a pentest.

    Args:
        pentest (str): The name of the pentest.
        attached_to (str): The id of the item the file is attached to.
        filetype (str): The type of the file to download.
        filename (Optional[str], optional): The name of the file to download. Defaults to None. If not specified and multiple files are found, 
            the file will be zipped and the zip file will be downloaded. 
            If specified, the file will be downloaded directly.

    Returns:
       Union[ErrorStatus, Response]: The file to download if successful, otherwise an error message and status code.
    """
    if filetype not in POSSIBLE_TYPES:
        return "Invalid filetype", 400
    if attached_to != "unassigned" and not is_valid_object_id(attached_to):
        return "Invalid attached_iid", 400
    filepath = os.path.join(local_path, pentest, filetype, str(attached_to))
    filepath = os.path.normpath(filepath)
    if not filepath.startswith(local_path):
        return "Invalid path", 400
    if filename is not None and filename != "":
        return _download_by_filename(filepath, filename)
    
    files = os.listdir(filepath)
    if len(files) == 1:
        filepath = os.path.join(filepath, files[0])
        if os.path.exists(filepath):
            return send_file(filepath)
    if len(files) >= 1:
        return send_zip_file(filepath, attached_to)
    if filename is not None:
        filename = os.path.basename(filename)
        filepath = os.path.join(local_path, "pollenisator", "file", "unassigned", filename)
        filepath = os.path.normpath(filepath)
        if not filepath.startswith(local_path):
            return "Invalid path", 400
        if os.path.exists(filepath):
            return send_file(filepath)
    return "File not found", 404

def _rm_proof_file(pentest: str, attached_to: str, filename: str) -> ErrorStatus:
    """
    Remove a proof file from a defect.
    """
    if not is_valid_object_id(attached_to):
        return "Invalid attached_iid", 400
    defect = Defect.fetchObject(pentest, {"_id": ObjectId(attached_to)})
    if defect is None:
        return "Defect not found", 404
    defect = cast(Defect, defect)
    try:
        defect.rmProof(filename)
    except FileNotFoundError:
        return "File not found", 404
    return "Success", 200

def _rm_file_file(pentest: str, attachment_id: str, filename: str) -> ErrorStatus:
    file_local_path = os.path.normpath(os.path.join(getMainDir(), "files"))
    filepath = os.path.join(file_local_path, pentest, "file", "unassigned", filename)
    filepath = os.path.normpath(filepath)
    if not filepath.startswith(file_local_path):
        return "Invalid path", 400
    try:
        dbclient.deleteFromDb(pentest, "attachments", {"attachment_id": attachment_id}, many=False, notify=True)
    except (ValueError, KeyError) as e:
        logger.error("Error deleting attachment: %s", str(e))
        return "Error deleting attachment", 500
    if os.path.exists(filepath):
        os.remove(filepath)
        return "Success", 200
    return "File not found", 404

@permission("pentester")
def rmFile(pentest: str,  attachment_id: str) -> ErrorStatus:
    """
    Remove a proof file from a defect in a pentest.

    Args:
        pentest (str): The name of the pentest.
        attachment_id (str): id to delete

    Returns:
        ErrorStatus: A success message if the file was successfully deleted, otherwise an error message and status code.
    """
    pentest = os.path.basename(pentest)
    attachment = dbclient.findInDb(pentest, "attachments", {"attachment_id": attachment_id}, False)
    if attachment is None:
        return "Attachment not found", 404
    filetype = attachment.get("type", None)
    attached_to = attachment.get("attached_to", "unassigned")
    filename = attachment.get("name", None)
    if filetype == "proof":
        return _rm_proof_file(pentest, attached_to, filename)
    elif filetype == "result":
        return "Results cannot be deleted", 403
    elif filetype == "file":
        return _rm_file_file(pentest, attachment_id, filename)
    else:
        return "Invalid filetype", 400
    
@permission("pentester")
def rmProofFile(pentest: str, attached_to: str, filename: str) -> ErrorStatus:
    """
    Remove a proof file from a defect in a pentest by its name.

    Args:
        pentest (str): The name of the pentest.
        attached_to (str): The id of the defect the file is attached to.
        filename (str): The name of the file to delete.

    Returns:
        ErrorStatus: A success message if the file was successfully deleted, otherwise an error message and status code.
    """
    pentest = os.path.basename(pentest)
    return _rm_proof_file(pentest, attached_to, filename)