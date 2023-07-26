import json
import os
import shutil
import connexion
from bson import ObjectId
from flask import send_file
import hashlib
from pollenisator.core.components.logger_config import logger
from datetime import datetime
from pollenisator.core.components.utils import listPlugin, loadPlugin, detectPlugins
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.components.utils import JSONDecoder, getMainDir
from pollenisator.core.controllers.toolcontroller import ToolController
from pollenisator.server.permission import permission

dbclient = DBClient.getInstance()
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
    msg, status, filepath = dbclient.do_upload(pentest, defect_iid, "proof", upfile)
    return msg, status
    
@permission("pentester")
def importExistingFile(pentest, upfile, body, **kwargs):
    from pollenisator.server.servermodels.tool import ServerTool
    user = kwargs["token_info"]["sub"]
    plugin = body.get("plugin", "auto-detect")
    default_target = json.loads(body.get("default_target", {}))
    cmdline = body.get("cmdline", "")

    md5File = md5(upfile.stream)
    upfile.stream.seek(0)
    name = upfile.filename.replace("/", "_")
    toolName = os.path.splitext(os.path.basename(name))[
        0] + md5File[:6]
    results_count = {}
    plugin_results = []
    error_msg = None
    ext = os.path.splitext(upfile.filename)[-1]
    if plugin == "auto-detect":
        # AUTO DETECT
        plugin_results = detectPlugins(pentest, upfile, cmdline, ext)
        for result in plugin_results:
            foundPlugin = result.get("plugin", None)
            if foundPlugin is not None:
                results_count[foundPlugin] = results_count.get(
                    foundPlugin, 0) + 1
    else:
        # SET PLUGIN 
        mod = loadPlugin(plugin)
        try:
            logger.info("PLUGIN for cmdline "+str(cmdline))
            notes, tags, lvl, targets = mod.Parse(pentest, upfile.stream, cmdline=cmdline, ext=ext,filename=upfile.filename)
            results_count[plugin] = results_count.get(plugin, 0) + 1
            plugin_results.append({"plugin":plugin, "notes":notes, "tags":tags, "lvl":lvl, "targets":targets})
        except Exception as e:
            error_msg = e
            logger.error("Plugin exception : "+str(e))
            notes = tags = lvl = targets = None
    if error_msg:
        return str(error_msg)
    # IF PLUGIN FOUND NOTHING, notes and tags are None
    for result in plugin_results:
        notes = result.get('notes')
        notes = "" if notes is None else notes
        tags = result.get('tags', [])
        tags = [] if tags is None else tags
        lvl = result.get('lvl')
        lvl = "imported" if lvl is None else lvl
        targets = result.get('targets', {})
        targets = {} if targets is None else targets
        if default_target:
            targets["default"] = default_target
            dbclient.send_notify(pentest, "Cheatsheet", default_target, "notif_terminal")
        for tag in tags:
            if isinstance(tag, tuple):
                level = tag[2] if tag[2] is not None else "info"
                color = tag[1] if tag[1] is not None else "transparent"
                tag_name = tag[0]
            else:
                color = "transparent"
                level = "info"
                tag_name = tag
            res = dbclient.doRegisterTag(pentest, tag_name, color, level)

        # ADD THE RESULTING TOOL TO AFFECTED
        for target in targets.values():
            date = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            if target is None:
                wave = None
                scope = None
                ip = None
                port = None
                proto = None
                check_iid = None
            else:
                lvl = target.get("lvl", lvl)
                wave = target.get("wave", None)
                scope = target.get("scope", None)
                ip = target.get("ip", None)
                port = target.get("port", None)
                proto = target.get("proto", None)
                check_iid = target.get("check_iid", None)
                tool_iid = target.get("tool_iid", None)
            if wave is None:
                wave = "Imported"
            if dbclient.findInDb(pentest, "waves", {"wave":wave}, False) is None:
                dbclient.insertInDb(pentest, "waves", {"wave":wave, "wave_commands":[]})
            tool_m = None
            if tool_iid is not None:
                tool_m = ServerTool.fetchObject(pentest, {"_id":ObjectId(tool_iid)})
                tool_m.notes = notes
                tool_m.scanner_ip = user
                tool_iid = tool_m.getId()

            if tool_m is None: # tool not found, create it
                tool_m = ServerTool(pentest).initialize("", check_iid, wave, name=toolName, scope=scope, ip=ip, port=port, proto=proto, lvl=lvl, text="",
                                            dated=date, datef=date, scanner_ip=user, status=["done"], notes=notes)
                ret = tool_m.addInDb()
                tool_iid = ret["iid"]
            ToolController(tool_m).setTags(tags)
            upfile.stream.seek(0)
            msg, status, filepath = dbclient.do_upload(pentest, str(tool_iid), "result", upfile)
            if status == 200:
                tool_m.plugin_used = plugin
                tool_m._setStatus(["done"], filepath)
    return results_count

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
    dbclient.updateInDb(pentest, "defects", {"_id": ObjectId(defect_iid)}, {"$pull":{"proofs":filename}})
    if not os.path.isfile(filepath):
        return "File not found", 404
    os.remove(filepath)
    return "Successfully deleted "+str(filename)



