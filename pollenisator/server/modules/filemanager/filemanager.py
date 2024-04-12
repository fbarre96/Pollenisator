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
from pollenisator.server.permission import permission

POSSIBLE_TYPES = ["proof", "result"]

dbclient = DBClient.getInstance()
local_path = os.path.normpath(os.path.join(getMainDir(), "files"))
try:
    os.makedirs(local_path)
except FileExistsError:
    pass

ErrorStatus = Tuple[str, int]
FileUploadResult = TypedDict('FileUploadResult', {'remote_path': str, 'msg': str, 'status': int})

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

@permission("pentester")
def upload(pentest: str, defect_iid: Union[Literal["unassigned"], str], upfile: werkzeug.datastructures.FileStorage) -> Union[FileUploadResult, ErrorStatus]:
    """
    Upload a file as proof for a defect.

    Args:
        pentest (str): The name of the pentest.
        defect_iid (Union[Literal["unassigned"], str]): The id of the defect.
        upfile (werkzeug.datastructures.FileStorage): The file to upload.

    Returns:
        Union[FileUploadResult, ErrorStatus]: A dictionary containing the remote path, message, and status if the upload was successful, otherwise a tuple containing the message and status.
    """
    msg, status, _filepath = dbclient.do_upload(pentest, defect_iid, "proof", upfile)
    if status == 200:
        if upfile.filename is not None:
            name = upfile.filename.replace("/", "_")
        else:
            name = "proof_"+str(time.time()).replace(".", "_")
        fileext = os.path.splitext(name)[-1]
        if fileext != ".png":
            name+=".png"
        return {"remote_path": f"files/{pentest}/download/proof/{defect_iid}/{name}", "msg":msg, "status":status}
    return msg, status

@permission("pentester")
def importExistingFile(pentest: str, upfile: werkzeug.datastructures.FileStorage, body: Dict[str, Any], **kwargs: Dict[str, Any]) -> Union[str, Dict[str, int]]:
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
    plugin = body.get("plugin", "auto-detect")
    default_target = json.loads(body.get("default_target", {}))
    cmdline = body.get("cmdline", "")

    md5File = md5(upfile.stream)
    upfile.stream.seek(0)
    name = upfile.filename.replace("/", "_") if upfile.filename is not None else "file_"+str(time.time()).replace(".", "_")
    toolName = os.path.splitext(os.path.basename(name))[
        0] + md5File[:6]
    results_count: Dict[str, int] = {}
    plugin_results = []
    error_msg = None
    ext = os.path.splitext(name)[-1]
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
            notes, tags, lvl, targets = mod.Parse(pentest, upfile.stream, cmdline=cmdline, ext=ext,filename=upfile.filename)
            results_count[plugin] = results_count.get(plugin, 0) + 1
            plugin_results.append({"plugin":plugin, "notes":notes, "tags":tags, "lvl":lvl, "targets":targets})
        except Exception as e:
            error_msg = e
            logger.error("Plugin exception : %s", str(e))
            traceback.print_exc()
            notes = tags = lvl = targets = None
    if error_msg:
        return str(error_msg)
    # IF PLUGIN FOUND NOTHING, notes and tags are None
    for result in plugin_results:
        notes = result.get('notes')
        notes = "" if notes is None else notes
        tags = result.get('tags', [])
        tags = [] if tags is None else tags
        lvl = result.get('lvl', "imported") 
        if lvl is None: # because result["lvl"] = None is defined
            lvl = "imported"
        targets = result.get('targets', {})
        targets = {} if targets is None else targets
        if default_target:
            targets["default"] = default_target
            dbclient.send_notify(pentest, "checkinstances", default_target, "notif_terminal")
        for tag in tags:
            tag = Tag(tag)
            dbclient.doRegisterTag(pentest, tag)

        # ADD THE RESULTING TOOL TO AFFECTED
        for target in targets.values():
            date = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            check_iid: Optional[ObjectId] = None
            tool_iid: Optional[ObjectId] = None
            if target is None:
                wave = None
                scope = None
                ip = None
                port = None
                proto = None
            else:
                lvl = str(target.get("lvl", lvl))
                wave = none_or_str(target.get("wave", None))
                scope = none_or_str(target.get("scope", None))
                ip = none_or_str(target.get("ip", None))
                port = none_or_str(target.get("port", None))
                proto = none_or_str(target.get("proto", None))
                try:
                    check_iid = None if target.get("check_iid", None) is None else ObjectId(target["check_iid"])
                except bson.errors.InvalidId:
                    check_iid = None
                try:
                    tool_iid = None if target.get("tool_iid", None) is None else ObjectId(target["tool_iid"])
                except bson.errors.InvalidId:
                    tool_iid = None
            if wave is None:
                wave = result.get("plugin", "")+"-Imported"
            if dbclient.findInDb(pentest, "waves", {"wave":wave}, False) is None:
                dbclient.insertInDb(pentest, "waves", {"wave":wave, "wave_commands":[]})
            tool_m = None
            if tool_iid is not None:
                tool_m = Tool.fetchObject(pentest, {"_id":ObjectId(tool_iid)})
                tool_m = cast(Tool, tool_m)
                tool_m.notes = notes
                tool_m.scanner_ip = user
                tool_iid = tool_m.getId()

            if tool_m is None: # tool not found, create it
                tool_m = Tool(pentest).initialize(None, check_iid, wave, name=toolName,
                                                  scope=scope, ip=ip, port=port, proto=proto,
                                                  lvl=str(lvl), text="",
                                                  dated=date, datef=date, scanner_ip=user,
                                                  status=["done"], notes=notes)
                ret = tool_m.addInDb()
                tool_iid = ObjectId(ret["iid"])
            if tool_m is not None:
                tool_m = cast(Tool, tool_m)
                tool_m.setTags(tags)
                upfile.stream.seek(0)
                _msg, status, filepath = dbclient.do_upload(pentest, str(tool_iid), "result", upfile)
                if status == 200:
                    tool_m.plugin_used = plugin
                    tool_m._setStatus(["done"], filepath)
    return results_count

@permission("pentester")
def listFiles(pentest: str, attached_iid: str, filetype: str) -> Union[ErrorStatus, List[str]]:
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
    if not is_valid_object_id(attached_iid):
        return "Invalid attached_iid", 400
    files: List[str] = []
    try:
        if filetype == "proof":
            defect = Defect.fetchObject(pentest, {"_id": ObjectId(attached_iid)})
            if defect is None:
                return "Defect not found", 404
            defect = cast(Defect, defect)
            try:
                files = defect.listProofFiles()
            except FileNotFoundError:
                files = []
        elif filetype == "result":
            tool = Tool.fetchObject(pentest, {"_id": ObjectId(attached_iid)})
            if tool is None:
                return "Tool not found", 404
            tool = cast(Tool, tool)
            files = tool.listResultFiles()
        else:
            return "Invalid filetype", 400
    except ValueError:
        return "Invalid path", 400
    except FileNotFoundError:
        return "File not found", 404
    return files

@permission("pentester")
def download(pentest: str, attached_iid: str, filetype: str, filename: Optional[str]=None) -> Union[ErrorStatus, Response]:
    """
    Download a file of a specific type attached to a specific item in a pentest.

    Args:
        pentest (str): The name of the pentest.
        attached_iid (str): The id of the item the file is attached to.
        filetype (str): The type of the file to download.
        filename (Optional[str], optional): The name of the file to download. Defaults to None. If not specified and multiple files are found, 
            the file will be zipped and the zip file will be downloaded. 
            If specified, the file will be downloaded directly.

    Returns:
       Union[ErrorStatus, Response]: The file to download if successful, otherwise an error message and status code.
    """
    if filetype not in POSSIBLE_TYPES:
        return "Invalid filetype", 400
    if not is_valid_object_id(attached_iid) and attached_iid != "unassigned":
        return "Invalid attached_iid", 400
    filepath = os.path.join(local_path, pentest, filetype, str(attached_iid))
    filepath = os.path.normpath(filepath)
    if not filepath.startswith(local_path):
        return "Invalid path", 400
    if filename is not None:
        filename = filename.replace("/", "_")
        filepath = os.path.join(filepath, os.path.basename(filename))
        if os.path.exists(filepath):
            return send_file(filepath)
    else:
        files = os.listdir(filepath)
        if len(files) == 1:
            filepath = os.path.join(filepath, files[0])
        elif len(files) >= 1:
            # generate a temp zip file
            temp_zipfile_dir = tempfile.mkdtemp()
            temp_zipfile_path = os.path.join(temp_zipfile_dir, str(attached_iid)+".zip")
            zipf = zipfile.ZipFile(temp_zipfile_path, 'w', zipfile.ZIP_DEFLATED)
            @after_this_request
            def remove_file(response):
                try:
                    os.remove(temp_zipfile_path)
                except Exception as error:
                    pass
                return response
            # Zip files in filepath directory and send it
            try:
                for root, dirs, files in os.walk(filepath):
                    for file in files:
                        zipf.write(os.path.join(root, file), os.path.relpath(os.path.join(root, file), filepath))
                zipf.close()
                return send_file(temp_zipfile_path)
            except Exception as e:
                return str(e), 500
    if os.path.exists(filepath):
        return send_file(filepath)
    return "File not found", 404

@permission("pentester")
def rmProof(pentest: str, defect_iid: str, filename: str) -> ErrorStatus:
    """
    Remove a proof file from a defect in a pentest.

    Args:
        pentest (str): The name of the pentest.
        defect_iid (str): The id of the defect the proof is attached to.
        filename (str): The name of the proof file to remove.

    Returns:
        ErrorStatus: A success message if the file was successfully deleted, otherwise an error message and status code.
    """
    if not is_valid_object_id(defect_iid):
        return "Invalid attached_iid", 400
    defect = Defect.fetchObject(pentest, {"_id": ObjectId(defect_iid)})
    if defect is None:
        return "Defect not found", 404
    defect = cast(Defect, defect)
    try:
        defect.rmProof(filename)
    except FileNotFoundError:
        return "File not found", 404
    return "Success", 200