import json
from pollenisator.core.Components.mongo import MongoCalendar
from pollenisator.core.Controllers.ToolController import ToolController
from pollenisator.server.ServerModels.Tool import ServerTool, update as tool_update
from bson import ObjectId
from datetime import datetime
from pollenisator.server.permission import permission


mongoInstance = MongoCalendar.getInstance()

@permission("user")
def listWorkers(pipeline=None):
    """Return workers documents from database
    Returns:
        Mongo result of workers. Cursor of dictionnary."""
    pipeline = {} if pipeline is None else pipeline
    pipeline = json.loads(pipeline)
    if not isinstance(pipeline, dict):
        return "Pipeline argument was not valid", 400
    ret = []
    for w in mongoInstance.getWorkers(pipeline):
        w["_id"] = str(w["_id"])
        ret.append(w)
    return ret

@permission("pentester", "body.db")
def setInclusion(name, body):
    "Set a worker inclusion in a pentest"
    return mongoInstance.setWorkerInclusion(name, body["db"], body["setInclusion"])

@permission("user")
def deleteWorker(name):
    res = mongoInstance.deleteWorker(name)
    if res is None:
        return "Worker not found", 404
    
    return {"n":int(res.deleted_count)}

def removeWorkers():
    workers = mongoInstance.getWorkers()
    count = 0
    for worker in workers:
        running_tools = worker.get("running_tools", [])
        for running_tool in running_tools:
            tool_m = ServerTool.fetchObject(running_tool["pentest"], {"_id":ObjectId(running_tool["iid"])})
            if "running" in tool_m.getStatus():
                tool_m.markAsNotDone()
                tool_update(running_tool["pentest"], running_tool["iid"], ToolController(tool_m).getData())
        deleteWorker(worker["name"])
        count += 1
    return {"n":int(count)}





@permission("user")
def getRegisteredCommands(name):
    return mongoInstance.getRegisteredCommands(name)

@permission("user")
def setCommandConfig(name, body):
    plugin = body["plugin"]
    command_name = body["command_name"]
    remote_bin = body["remote_bin"]
    worker = mongoInstance.getWorker(name)
    if worker is None:
        return "Worker not found", 404
    from pollenisator.api import socketio, sockets
    socketio.emit('editToolConfig', {'command_name': command_name, "remote_bin":remote_bin,"plugin": plugin}, room=sockets[name])
    return True

@permission("worker")
def registerWorker(body):
    name = body["name"]
    command_names = body["command_names"]
    res = mongoInstance.registerCommands(name, command_names)
    return res

def unregister(name):
    worker = mongoInstance.getWorker(name)
    if worker is not None:
        running_tools = worker.get("running_tools", [])
        for running_tool in running_tools:
            tool_m = ServerTool.fetchObject(running_tool["pentest"], {"_id":ObjectId(running_tool["iid"])})
            if "running" in tool_m.getStatus():
                tool_m.markAsNotDone()
                tool_update(running_tool["pentest"], running_tool["iid"], ToolController(tool_m).getData())
        mongoInstance.deleteFromDb("pollenisator", "workers", {"name": name}, False, True)
        return True
    return "Worker not Found", 404
