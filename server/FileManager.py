import json
import os
import shutil
from bson import ObjectId
from flask import send_file
import hashlib
from datetime import datetime
from core.Components.Utils import listPlugin, loadPlugin
from core.Components.mongo import MongoCalendar
from core.Components.Utils import JSONDecoder
from server.permission import permission

mongoInstance = MongoCalendar.getInstance()
local_path = "/etc/PollenisatorAPI/files"
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
    msg, status, filepath = _upload(pentest, defect_iid, "proof", upfile)
    return msg, status
@permission("pentester")
def importExistingFile(pentest, upfile, plugin):
    from server.ServerModels.Tool import ServerTool
    mongoInstance.connectToDb(pentest)
    md5File = md5(upfile.stream)
    upfile.stream.seek(0)
    name = upfile.filename.replace("/", "_")
    toolName = os.path.splitext(os.path.basename(name))[
        0] + md5File[:6]
    results = {}
    if plugin == "auto-detect":
        # AUTO DETECT
        foundPlugin = "Ignored"
        for pluginName in listPlugin():
            if foundPlugin != "Ignored":
                break
            mod = loadPlugin(pluginName)
            if mod.autoDetectEnabled():
                notes, tags, lvl, targets = mod.Parse(pentest, upfile.stream)
                upfile.stream.seek(0)
                if notes is not None and tags is not None:
                    foundPlugin = pluginName
        results[foundPlugin] = results.get(
            foundPlugin, 0) + 1
    else:
        # SET PLUGIN 
        mod = loadPlugin(plugin)
        notes, tags, lvl, targets = mod.Parse(pentest, upfile.stream)
        results[plugin] = results.get(
            plugin, 0) + 1
    # IF PLUGIN FOUND SOMETHING
    if notes is not None and tags is not None:
        # ADD THE RESULTING TOOL TO AFFECTED
        for target in targets.values():
            date = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            if target is None:
                scope = None
                ip = None
                port = None
                proto = None
            else:
                scope = target.get("scope", None)
                ip = target.get("ip", None)
                port = target.get("port", None)
                proto = target.get("proto", None)
            mongoInstance.connectToDb(pentest)
            mongoInstance.insert("waves", {"wave":"Imported", "wave_commands":[]})
            tool_m = ServerTool().initialize(toolName, "Imported", scope=scope, ip=ip, port=port, proto=proto, lvl=lvl, text="",
                                        dated=date, datef=date, scanner_ip="Imported", status="done", notes=notes, tags=tags)
            tool_m.addInDb()
            upfile.stream.seek(0)
            msg, status, filepath = _upload(pentest, tool_m.getId(), "result", upfile)
            if status == 200:
                mongoInstance.update("tools", {"_id":ObjectId(tool_m.getId())}, {"resultfile":  filepath})
    return results


def _upload(pentest, attached_iid, filetype, upfile):
    mongoInstance.connectToDb(pentest)
    filepath = os.path.join(local_path, pentest, filetype, attached_iid)
    if filetype == "result":
        res = mongoInstance.find("tools", {"_id": ObjectId(attached_iid)}, False)
        if res is None:
            return "The given iid does not match an existing tool", 404, ""
        else:
            if os.path.isdir(filepath):
                files = os.listdir(filepath)
                for existing_file in files:
                    os.remove(os.path.join(filepath, files[0]))
    elif filetype == "proof":
        res = mongoInstance.find("defects", {"_id": ObjectId(attached_iid)}, False)
        if res is None:
            return "The given iid does not match an existing defect", 404, ""
    else:
        return "Filetype is not proof nor result", 400, ""
    
    try:
        os.makedirs(filepath)
    except FileExistsError:
        pass
    name = upfile.filename.replace("/", "_")
    filepath = os.path.join(filepath, name)
    with open(filepath, "wb") as f:
        f.write(upfile.stream.read())
    if filetype == "proof":
        mongoInstance.update("defects", {"_id": ObjectId(attached_iid)}, {"$push":{"proofs":name}})
    return name + " was successfully uploaded", 200, filepath

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
    return send_file(filepath, attachment_filename=filename.replace("/", "_"))

@permission("pentester")
def rmProof(pentest, defect_iid, filename):
    mongoInstance.connectToDb(pentest)
    filename = filename.replace("/", "_")
    filepath = os.path.join(local_path, pentest, "proof", defect_iid, filename)
    mongoInstance.update("defects", {"_id": ObjectId(defect_iid)}, {"$pull":{"proofs":filename}})
    if not os.path.isfile(filepath):
        return "File not found", 404
    os.remove(filepath)
    return "Successfully deleted "+str(filename)

def getProofPath(pentest, defect_iid):
    return os.path.join(local_path, pentest, "proof", str(defect_iid))

def deletePentestFiles(pentest):
    proofspath = os.path.join(local_path, pentest, "proof")
    if os.path.isdir(proofspath):
        shutil.rmtree(proofspath)
    resultspath = os.path.join(local_path, pentest, "result")
    if os.path.isdir(resultspath):
        shutil.rmtree(resultspath)