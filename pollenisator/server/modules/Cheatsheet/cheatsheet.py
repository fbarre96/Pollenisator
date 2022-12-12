from bson import ObjectId
from pollenisator.core.Components.mongo import MongoCalendar
from pollenisator.server.ServerModels.Element import ServerElement
from pollenisator.server.permission import permission

class CheckItem(ServerElement):
    coll_name = 'cheatsheet'
    def __init__(self, pentest, valuesFromDb=None):
        mongoInstance = MongoCalendar.getInstance()
        if pentest != "":
            self.pentest = pentest
        elif mongoInstance.calendarName != "":
            self.pentest = mongoInstance.calendarName
        else:
            raise ValueError("An empty pentest name was given and the database is not set in mongo instance.")
        if valuesFromDb is None:
            valuesFromDb = {}
        if valuesFromDb is None:
            valuesFromDb = {}
        self.initialize(pentest, valuesFromDb.get("_id"), valuesFromDb.get("title"),  valuesFromDb.get("pentest_types"), valuesFromDb.get("description"), valuesFromDb.get("category"),
            valuesFromDb.get("check_type"), valuesFromDb.get("step"), valuesFromDb.get("parent"), 
            valuesFromDb.get("commands"), valuesFromDb.get(""), valuesFromDb.get("defects"), valuesFromDb.get("infos"))

    def initialize(self, pentest, _id, title, pentest_types=None, description="", category="", check_type="manual", step=1, parent=None, commands=None, script=None, defects=None, infos=None):

        self._id = _id
        self.type = "checkitem"
        self.title = title
        self.description = description
        self.category = category
        self.check_type = check_type
        self.step = step
        self.parent = parent
        self.commands = [] if commands is None else commands
        self.script = script
        self.pentest_types = [] if pentest_types is None else pentest_types
        self.defects = [] if defects is None else defects
        self.infos = {} if infos is None else infos
        mongoInstance = MongoCalendar.getInstance()
        if pentest != "":
            self.pentest = pentest
        elif mongoInstance.calendarName != "":
            self.pentest = mongoInstance.calendarName
        else:
            raise ValueError("An empty pentest name was given and the database is not set in mongo instance.")
        return self

    @classmethod
    def fetchObjects(cls, pipeline):
        """Fetch many commands from database and return a Cursor to iterate over model objects
        Args:
            pipeline: a Mongo search pipeline (dict)
        Returns:
            Returns a cursor to iterate on model objects
        """
        mongoInstance = MongoCalendar.getInstance()
        pipeline["type"] = "checkitem"
        ds = mongoInstance.findInDb("pollenisator", cls.coll_name, pipeline, True)
        if ds is None:
            return None
        for d in ds:
            # disabling this error as it is an abstract function
            yield cls("pollenisator",d)  #  pylint: disable=no-value-for-parameter
    
    @classmethod
    def fetchObject(cls, pipeline):
        """Fetch many commands from database and return a Cursor to iterate over model objects
        Args:
            pipeline: a Mongo search pipeline (dict)
        Returns:
            Returns a cursor to iterate on model objects
        """
        mongoInstance = MongoCalendar.getInstance()
        pipeline["type"] = "checkitem"
        d = mongoInstance.findInDb("pollenisator", cls.coll_name, pipeline, False)
        if d is None:
            return None
        return cls("pollenisator", d)
  
    def getData(self):
        return {"_id": self._id, "type":self.type, "title":self.title,"pentest_types":self.pentest_types, "description": self.description, "category":self.category,
                "check_type":self.check_type, "step":self.step, "parent":self.parent,
                "commands":self.commands, "script":self.script, "defects":self.defects, "infos":self.infos}

    def addInDb(self):
        return doInsert(self.pentest, self.getData())



@permission("user")
def getModuleInfo():
    return {"registerLvls": []}

def doInsert(pentest, data):
    if "_id" in data:
        del data["_id"]
    if data.get("parent") is not None:
        parent_iid = ObjectId(data.get("parent"))
        parent_m = CheckItem.fetchObject({"_id":parent_iid})
        if parent_m is None:
            return "Parent not found", 404
        brothers = list(CheckItem.fetchObjects({"parent":str(parent_iid)}))
        if len(brothers) > 0:
            step = max([x.step for x in brothers])+1
        else:
            step = 1
        data["step"] = step
    mongoInstance = MongoCalendar.getInstance()
    data["type"] = "checkitem"
    existing = CheckItem.fetchObject({"title":data["title"]})
    if existing is not None:
        return {"res":False, "iid":existing.getId()}
    
    ins_result = mongoInstance.insertInDb(
        pentest, CheckItem.coll_name, data, True)
    iid = ins_result.inserted_id
    return {"res": True, "iid": iid}

@permission("user")
def insert(body):
    """insert cheatsheet information
    """
    if "type" in body:
        del body["type"]
    if "_id" in body:
        del body["_id"]
    checkitem = CheckItem("pollenisator", body)
    data = checkitem.getData()
    return doInsert("pollenisator", data)

@permission("user")
def delete(iid):
    """delete cheatsheet item
    """
    mongoInstance = MongoCalendar.getInstance()
    existing = CheckItem.fetchObject({"_id":ObjectId(iid)})
    if existing is None:
        return "Not found", 404
    calendars = mongoInstance.listCalendarNames()
    for calendar in calendars:
        mongoInstance.deleteFromDb(calendar, CheckItem.coll_name, {"check_iid":ObjectId(iid)}, many=True, notify=True)
    res = mongoInstance.deleteFromDb("pollenisator", CheckItem.coll_name, {"_id":ObjectId(iid)}, many=False, notify=True)
    if res is None:
        return 0
    return res.deleted_count



@permission("user")
def update(iid, body):
    checkitem = CheckItem("pollenisator", body)
    mongoInstance = MongoCalendar.getInstance()
    existing = CheckItem.fetchObject({"_id": ObjectId(iid)})
    if existing is None:
        return "Not found", 404
    if checkitem.title != existing.title:
        return "Forbidden", 403
    if "type" in body:
        del body["type"]
    if "_id" in body:
        del body["_id"]
    
    mongoInstance.updateInDb("pollenisator", CheckItem.coll_name, {"_id": ObjectId(iid), "type":"checkitem"}, {"$set": body}, False, True)
    return True
