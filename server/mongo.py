import json
from bson import ObjectId
from datetime import datetime
from core.Components.mongo import MongoCalendar
from core.Components.Utils import JSONDecoder
mongoInstance = MongoCalendar.getInstance()

validCollections = ["group_commands", "commands", "settings"]


def status():
    mongoInstance.connect()
    return mongoInstance.client != None

def update(pentest, collection, data):
    pipeline = data["pipeline"] if data["pipeline"] is not None else "{}"
    if isinstance(pipeline, str):
        pipeline = json.loads(pipeline, cls=JSONDecoder)
    if not isinstance(pipeline, dict):
        return "Pipeline argument was not valid", 400
    updatePipeline = data["updatePipeline"]
    if isinstance(updatePipeline, str):
        updatePipeline = json.loads(updatePipeline, cls=JSONDecoder)
    if not isinstance(updatePipeline, dict):
        return "Pipeline argument was not valid", 400
    if pentest == "pollenisator":
        if collection not in validCollections:
            return "Collection argument is not a valid pollenisator collection", 403
    elif pentest not in mongoInstance.listCalendars():
        return "Pentest argument is not a valid pollenisator pentest", 403
    return mongoInstance.updateInDb(pentest, collection, pipeline, updatePipeline, data["many"], data["notify"])

def insert(pentest, collection, data):
    pipeline = data["pipeline"]
    if isinstance(pipeline, str):
        pipeline = json.loads(pipeline, cls=JSONDecoder)
    if not isinstance(pipeline, dict):
        return "Pipeline argument was not valid", 400
    if pentest == "pollenisator":
        if collection not in validCollections:
            return "Collection argument is not a valid pollenisator collection", 403
    elif pentest not in mongoInstance.listCalendars():
        return "Pentest argument is not a valid pollenisator pentest", 403
    res = mongoInstance.insertInDb(pentest, collection, pipeline, data["parent"], data["notify"])
    return str(res.inserted_id)

def find(pentest, collection, data):
    pipeline = data["pipeline"]
    if isinstance(pipeline, str):
        print(str(pipeline))
        pipeline = json.loads(pipeline, cls=JSONDecoder)
    if not isinstance(pipeline, dict):
        return "Pipeline argument was not valid", 400
    if pentest == "pollenisator":
        if collection not in validCollections:
            return "Collection argument is not a valid pollenisator collection", 403
    elif pentest not in mongoInstance.listCalendars():
        return "Pentest argument is not a valid pollenisator pentest", 403
    res = mongoInstance.findInDb(pentest, collection, pipeline, data["many"])
    if isinstance(res, dict):
        return res
    elif res is None:
        return "Not found", 404
    else:
        ret = []
        for r in res:
            r["_id"] = str(r["_id"])
            ret.append(r)
        return ret

def count(pentest, collection, data):
    pipeline = data["pipeline"]
    if isinstance(pipeline, str):
        pipeline = json.loads(pipeline, cls=JSONDecoder)
    if pentest == "pollenisator":
        if collection not in validCollections:
            return "Collection argument is not a valid pollenisator collection", 403
    if not isinstance(pipeline, dict):
        return "Pipeline argument was not valid", 400
    elif pentest not in mongoInstance.listCalendars():
        return "Pentest argument is not a valid pollenisator pentest", 403
    res = mongoInstance.findInDb(pentest, collection, pipeline, True).count()
    return res

def fetchNotifications(pentest, fromTime):
    res = mongoInstance.fetchNotifications(pentest, fromTime)
    if res is None:
        return []
    return [n for n in res]

def pushNotification(data):
    mongoInstance = MongoCalendar.getInstance()
    mongoInstance.insertInDb("pollenisator", "notifications", {"db":data["pentest"], "collection":data["collection"], "iid":data["iid"], "action":data["action"], "parentId":data["parentId"], "time":datetime.now()}, False)
    
def aggregate(pentest, collection, pipelines):
    ret = []
    if pentest == "pollenisator":
        if collection not in validCollections:
            return "Collection argument is not a valid pollenisator collection", 403
    elif pentest not in mongoInstance.listCalendars():
        return "Pentest argument is not a valid pollenisator pentest", 403
    res = mongoInstance.aggregateFromDb(pentest, collection, pipelines)
    for r in res:
        ret.append(r)
    return ret

def delete(pentest, collection, data):
    pipeline = data["pipeline"]
    if isinstance(pipeline, str):
        pipeline = json.loads(pipeline, cls=JSONDecoder)
    if not isinstance(pipeline, dict):
        return "Pipeline argument was not a valid dictionnary", 400
    if pentest == "pollenisator":
        if collection not in validCollections:
            return "Collection argument is not a valid pollenisator collection", 403
    elif pentest not in mongoInstance.listCalendars():
        return "Pentest argument is not a valid pollenisator pentest", 403
    res = mongoInstance.deleteFromDb(pentest, collection, pipeline, data["many"], data["notify"])
    if res is None:
        return
    else:
        return res.deleted_count

def listPentests():
    ret = mongoInstance.listCalendars()
    if ret:
        return ret
    else:
        return "Server connection issue", 503

def deletePentest(pentest):
    ret = mongoInstance.doDeleteCalendar(pentest)
    if ret:
        return "Successful deletion"
    else:
        return  "Unknown pentest", 404

def registerCalendar(pentest):
    ret, msg = mongoInstance.registerCalendar(pentest, False, False)
    if ret:
        return msg
    else:
        return msg, 403

def getSettings():
    res = mongoInstance.findInDb("pollenisator", "settings", {}, True)
    if res is None:
        return []
    return [s for s in res]

def getSetting(data):
    pipeline = data["pipeline"]
    if isinstance(pipeline, str):
        pipeline = json.loads(pipeline, cls=JSONDecoder)
    if not isinstance(pipeline, dict):
        return "Pipeline argument was not valid", 400
    return mongoInstance.findInDb("pollenisator", "settings", pipeline, False)

def createSetting(data):
    key = data['key']
    value = data["value"]
    return mongoInstance.insertInDb("pollenisator", "settings", {"key":key, "value":value})

def updateSetting(data):
    key = data['key']
    value = data["value"]
    return mongoInstance.updateInDb("pollenisator", "settings", {
                    "key": key}, {"$set": {"value": value}})