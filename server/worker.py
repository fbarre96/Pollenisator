import json
from core.Components.mongo import MongoCalendar
from core.Controllers.ToolController import ToolController
from server.ServerModels.Tool import ServerTool, update as tool_update
from bson import ObjectId
from datetime import datetime
mongoInstance = MongoCalendar.getInstance()


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

def setExclusion(name, worker):
    "Set a worker exclusion from database"
    return mongoInstance.setWorkerExclusion(name, worker["db"], worker["setExcluded"])

def deleteWorker(name):
    res = mongoInstance.deleteWorker(name)
    if res is None:
        return "Worker not found", 404
    
    return {"n":int(res.deleted_count)}

def removeInactiveWorkers():
    workers = mongoInstance.getInactiveWorkers()
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

def registerCommands(name, command_names):
    res = mongoInstance.registerCommands(name, command_names)
    return res

def getRegisteredCommands(name):
    return mongoInstance.getRegisteredCommands(name)

def setCommandConfig(name, data):
    plugin = data["plugin"]
    command_name = data["command_name"]
    remote_bin = data["remote_bin"]
    worker = mongoInstance.getWorker(name)
    if worker is None:
        return "Worker not found", 404
    mongoInstance.insertInDb("pollenisator", "instructions", {"worker":name, "date":datetime.now(), "function":"editToolConfig", "args":[command_name, remote_bin, plugin]}, False)
    return True

def registerWorker(data):
    name = data["name"]
    command_names = data["command_names"]
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

def getInstructions(name):
    worker = mongoInstance.getWorker(name)
    if worker is None:
        return "Worker not Found", 404
    mongoInstance.updateWorkerLastHeartbeat(name)
    instructions = mongoInstance.findInDb("pollenisator", "instructions", {"worker":name}, True)
    data = list(instructions)
    mongoInstance.deleteFromDb("pollenisator", "instructions", {"worker":name}, True, False)
    return data

def deleteInstruction(name, instruction_iid):
    worker = mongoInstance.getWorker(name)
    if worker is None:
        return "Worker not Found", 404
    res = mongoInstance.deleteFromDb("pollenisator", "instructions", {"_id":ObjectId(instruction_iid)})
    if res is None:
        return "Instruction not found", 404
    return res.deleted_count