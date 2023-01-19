import json
import os
import shutil
import connexion
from bson import ObjectId
from flask import send_file
import hashlib
from pollenisator.core.Components.logger_config import logger
from datetime import datetime
from pollenisator.core.Components.Utils import listPlugin, loadPlugin
from pollenisator.core.Components.mongo import MongoCalendar
from pollenisator.core.Components.Utils import JSONDecoder, getMainDir
from pollenisator.server.permission import permission

mongoInstance = MongoCalendar.getInstance()
local_path = os.path.join(getMainDir(), "files")
try:
    os.makedirs(local_path)
except FileExistsError:
    pass


def md5(f):
    """Compute md5 hash of the given file name.
    Args:
        fname: path to the file you want to compute the md5 of.
    Return:
        The digested hash of the file in an hexadecimal string format.
    """
    hash_md5 = hashlib.md5()
    for chunk in iter(lambda: f.read(4096), b""):
        hash_md5.update(chunk)
    return hash_md5.hexdigest()

@permission("pentester")
def upload(pentest, defect_iid, upfile):
    msg, status, filepath = mongoInstance.do_upload(pentest, defect_iid, "proof", upfile)
    return msg, status
    
@permission("pentester")
def importExistingFile(pentest, upfile, body, **kwargs):
    from pollenisator.server.ServerModels.Tool import ServerTool
    user = kwargs["token_info"]["sub"]
    plugin = body.get("plugin", "auto-detect")
    default_target = body.get("default_target", "")
    cmdline = body.get("cmdline", "")
    default_target_objects = None
    if default_target != "":
        default_target_objects = default_target.split("|")
        if len(default_target_objects) != 6:
            return "Default target is badly crafted", 400

    md5File = md5(upfile.stream)
    upfile.stream.seek(0)
    name = upfile.filename.replace("/", "_")
    toolName = os.path.splitext(os.path.basename(name))[
        0] + md5File[:6]
    results = {}
    error_msg = None
    ext = os.path.splitext(upfile.filename)[-1]
    if plugin == "auto-detect":
        # AUTO DETECT
        foundPlugin = "Ignored"
        for pluginName in listPlugin():
            if foundPlugin != "Ignored":
                break
            mod = loadPlugin(pluginName)
            if mod.autoDetectEnabled():
                notes, tags, lvl, targets = mod.Parse(pentest, upfile.stream, cmdline=cmdline, ext=ext, filename=upfile.filename)
                upfile.stream.seek(0)
                if notes is not None and tags is not None:
                    foundPlugin = pluginName
        results[foundPlugin] = results.get(
            foundPlugin, 0) + 1
    else:
        # SET PLUGIN 
        mod = loadPlugin(plugin)
        try:
            logger.info("PLUGIN for cmdline "+str(cmdline))
            notes, tags, lvl, targets = mod.Parse(pentest, upfile.stream, cmdline=cmdline, ext=ext,filename=upfile.filename)
            results[plugin] = results.get(
                plugin, 0) + 1
        except Exception as e:
            error_msg = e
            logger.error("Plugin exception : "+str(e))
            notes = tags = lvl = targets = None
    if error_msg:
        return str(error_msg)
    # IF PLUGIN FOUND SOMETHING
    if notes is not None and tags is not None:
        if default_target_objects:
            targets["default"] = {"lvl":default_target_objects[0], "wave":default_target_objects[1],"scope":default_target_objects[2], "ip":default_target_objects[3], 
                                "port":default_target_objects[4], "proto":default_target_objects[5]}
        for tag in tags:
            res = mongoInstance.doRegisterTag(pentest, tag)

        # ADD THE RESULTING TOOL TO AFFECTED
        for target in targets.values():
            date = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            if target is None:
                wave = None
                scope = None
                ip = None
                port = None
                proto = None
            else:
                lvl = target.get("lvl", lvl)
                wave = target.get("wave", None)
                scope = target.get("scope", None)
                ip = target.get("ip", None)
                port = target.get("port", None)
                proto = target.get("proto", None)
            if wave is None:
                wave = "Imported"
            if mongoInstance.findInDb(pentest, "waves", {"wave":wave}, False) is None:
                mongoInstance.insertInDb(pentest, "waves", {"wave":wave, "wave_commands":[]})
            tool_m = ServerTool(pentest).initialize("", None, wave, name=toolName, scope=scope, ip=ip, port=port, proto=proto, lvl=lvl, text="",
                                        dated=date, datef=date, scanner_ip=user, status=["done"], notes=notes, tags=tags)
            ret = tool_m.addInDb()
            upfile.stream.seek(0)
            msg, status, filepath = mongoInstance.do_upload(pentest, str(ret["iid"]), "result", upfile)
            if status == 200:
                mongoInstance.updateInDb(pentest, "tools", {"_id":ObjectId(ret["iid"])}, {"$set":{"resultfile":  filepath, "plugin_used":plugin}})
    return results

@permission("pentester")
def listFiles(pentest, attached_iid, filetype):
    filepath = os.path.join(local_path, pentest, filetype, attached_iid)
    files = os.listdir(filepath)
    return files

@permission("pentester")
def download(pentest, attached_iid, filetype, filename):
    if filetype == "result":
        filepath = os.path.join(local_path, pentest, filetype, attached_iid)
        files = os.listdir(filepath)
        if len(files) == 1:
            filepath = os.path.join(filepath, files[0])
        else:
            return "No result file found for given tool", 404
    else:
        filepath = os.path.join(local_path, pentest, filetype, attached_iid, filename.replace("/", "_"))
    if not os.path.isfile(filepath):
        return "File not found", 404
    try:
        return send_file(filepath, attachment_filename=filename.replace("/", "_"))
    except TypeError as e: # python3.10.6 breaks https://stackoverflow.com/questions/73276384/getting-an-error-attachment-filename-does-not-exist-in-my-docker-environment
        return send_file(filepath, download_name=filename.replace("/", "_"))

@permission("pentester")
def rmProof(pentest, defect_iid, filename):
    filename = filename.replace("/", "_")
    filepath = os.path.join(local_path, pentest, "proof", defect_iid, filename)
    mongoInstance.updateInDb(pentest, "defects", {"_id": ObjectId(defect_iid)}, {"$pull":{"proofs":filename}})
    if not os.path.isfile(filepath):
        return "File not found", 404
    os.remove(filepath)
    return "Successfully deleted "+str(filename)



