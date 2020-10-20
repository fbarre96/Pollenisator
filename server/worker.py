import json
from core.Components.mongo import MongoCalendar

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

def setExclusion(worker):
    "Set a worker exclusion from database"
    return mongoInstance.setWorkerExclusion(worker["worker"], worker["db"], worker["setExcluded"])

def deleteWorker(name):
    res = mongoInstance.deleteWorker(name)
    if res is None:
        return "Worker not found", 404
    
    return {"n":int(res.deleted_count)}

def removeInactiveWorkers():
    count = mongoInstance.removeInactiveWorkers()
    return {"n":int(count)}

def updateHeartbeat(name):
    return mongoInstance.updateWorkerLastHeartbeat(name)

def registerCommands(name, command_names):
    res = mongoInstance.registerCommands(name, command_names)
    if res:
        return 200, "success"
    else:
        return 404, "Not found"

def getRegisteredCommands(name):
    return mongoInstance.getRegisteredCommands(name)