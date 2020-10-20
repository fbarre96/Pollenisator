import json
from bson import ObjectId
from core.Components.mongo import MongoCalendar
mongoInstance = MongoCalendar.getInstance()

validCollections = ["group_commands", "commands", "settings"]

class JSONDecoder(json.JSONDecoder):
    def __init__(self, *args, **kwargs):
        json.JSONDecoder.__init__(self, object_hook=self.object_hook, *args, **kwargs)
    def object_hook(self, dct):
        for k,v in dct.items():
            if 'ObjectId|' in str(v):
                dct[k] = ObjectId(v.split('ObjectId|')[1])
        return dct

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
    res = mongoInstance.insertInDb(pentest, collection, pipeline, data["notify"])
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

def fetchNotifications(pentest):
    res = mongoInstance.fetchNotifications(pentest)
    if res is None:
        return []
    return res

def pushNotification(data):
    mongoInstance = MongoCalendar.getInstance()
    mongoInstance.insertInDb("pollenisator", "notifications", {"db":data["pentest"], "collection":data["collection"], "iid":data["iid"], "action":data["action"], "parentId":data["parentId"]}, False)
    
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
    return mongoInstance.deleteFromDb(pentest, collection, pipeline, data["many"], data["notify"])

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
    return mongoInstance.findInDb("pollenisator", "settings", pipeline, True)

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