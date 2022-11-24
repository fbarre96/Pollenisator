from bson import ObjectId
from pollenisator.core.Components.mongo import MongoCalendar
from pollenisator.server.ServerModels.Element import ServerElement
from pollenisator.server.ServerModels.Tool import ServerTool
from pollenisator.server.ServerModels.Command import ServerCommand
from pollenisator.server.modules.Cheatsheet.cheatsheet import CheckItem
from pollenisator.server.permission import permission

class CheckInstance(ServerElement):
    coll_name = 'cheatsheet'

    def __init__(self, pentest, valuesFromDb=None):
        mongoInstance = MongoCalendar.getInstance()
        if pentest != "":
            self.pentest = pentest
        elif mongoInstance.calendarName != "":
            self.pentest = mongoInstance.calendarName
        else:
            raise ValueError("An empty pentest name was given and the database is not set in mongo instance.")
        mongoInstance.connectToDb(self.pentest)
        if valuesFromDb is None:
            valuesFromDb = {}
        if valuesFromDb is None:
            valuesFromDb = {}
        self.initialize(pentest, valuesFromDb.get("_id"), valuesFromDb.get("check_iid"), valuesFromDb.get("parent", None), valuesFromDb.get("status", ""), valuesFromDb.get("notes", ""))

    def initialize(self, pentest, _id, check_iid, parent, status, notes):
        self._id = _id
        self.parent = parent
        self.type = "checkinstance"
        self.check_iid = check_iid
        self.status = status
        self.notes = notes
        mongoInstance = MongoCalendar.getInstance()
        if pentest != "":
            self.pentest = pentest
        elif mongoInstance.calendarName != "":
            self.pentest = mongoInstance.calendarName
        else:
            raise ValueError("An empty pentest name was given and the database is not set in mongo instance.")
        return self

    @classmethod
    def fetchObjects(cls, pentest, pipeline):
        """Fetch many commands from database and return a Cursor to iterate over model objects
        Args:
            pipeline: a Mongo search pipeline (dict)
        Returns:
            Returns a cursor to iterate on model objects
        """
        mongoInstance = MongoCalendar.getInstance()
        pipeline["type"] = "checkinstance"
        ds = mongoInstance.findInDb(pentest, cls.coll_name, pipeline, True)
        if ds is None:
            return None
        for d in ds:
            # disabling this error as it is an abstract function
            yield cls(pentest,d)  #  pylint: disable=no-value-for-parameter
    
    @classmethod
    def fetchObject(cls, pentest, pipeline):
        """Fetch many commands from database and return a Cursor to iterate over model objects
        Args:
            pipeline: a Mongo search pipeline (dict)
        Returns:
            Returns a cursor to iterate on model objects
        """
        mongoInstance = MongoCalendar.getInstance()
        pipeline["type"] = "checkinstance"
        d = mongoInstance.findInDb(pentest, cls.coll_name, pipeline, False)
        if d is None:
            return None
        return cls(pentest, d)
  
    def getData(self):
        return {"_id": self._id, "type":self.type, "check_iid": self.check_iid, "parent":self.parent, "status":self.status, "notes":self.notes}

    def addInDb(self):
        return doInsert(self.pentest, self.getData())

    @classmethod
    def createFromCheckItem(cls, pentest, checkItem):
        parent = None
        if checkItem.parent is not None:
            check_instance_parent = cls.fetchObject(pentest, {"check_iid":str(checkItem.parent)})
            parent = str(check_instance_parent.getId())
        checkinstance = CheckInstance(pentest).initialize(pentest, None, str(checkItem._id), parent, "", "")
        return checkinstance.addInDb()


def doInsert(pentest, data):
    if "_id" in data:
        del data["_id"]
    mongoInstance = MongoCalendar.getInstance()
    data["type"] = "checkinstance"
    existing = CheckInstance.fetchObject(pentest, {"check_iid":str(data["check_iid"])})
    if existing is not None:
        return {"res":False, "iid":existing.getId()}
    ins_result = mongoInstance.insertInDb(
        pentest, CheckInstance.coll_name, data, True)
    iid = ins_result.inserted_id
    return {"res": True, "iid": iid}

def addCheckInstancesToPentest(pentest, pentest_type):
    mongoInstance = MongoCalendar.getInstance()
    checkItems = CheckItem.fetchObjects({"pentest_types":pentest_type})
    for checkItem in checkItems:
        CheckInstance.createFromCheckItem(pentest, checkItem)
    return True

@permission("pentester")
def insert(pentest, body):
    """insert cheatsheet checkItem instance
    """
    if "type" in body:
        del body["type"]
    if "_id" in body:
        del body["_id"]
    if pentest == "pollenisator":
        return "Forbidden", 403
    checkinstance = CheckInstance(pentest, body)
    data = checkinstance.getData()
    return doInsert(pentest, data)

@permission("pentester")
def delete(pentest, iid):
    """delete cheatsheet item
    """
    mongoInstance = MongoCalendar.getInstance()
    if pentest == "pollenisator":
        return "Forbidden", 403
    existing = CheckInstance.fetchObject(pentest, {"_id":ObjectId(iid)})
    if existing is None:
        return "Not found", 404

    res = mongoInstance.deleteFromDb(pentest, CheckInstance.coll_name, {"_id":ObjectId(iid)}, many=False, notify=True)
    if res is None:
        return 0
    return res.deleted_count



@permission("pentester")
def update(pentest, iid, body):
    if pentest == "pollenisator":
        return "Forbidden", 403
    checkinstance = CheckInstance(pentest, body)
    mongoInstance = MongoCalendar.getInstance()
    existing = CheckInstance.fetchObject(pentest, {"_id": ObjectId(iid)})
    if existing is None:
        return "Not found", 404
    if checkinstance.check_iid != existing.check_iid:
        return "Forbidden", 403
    if "type" in body:
        del body["type"]
    if "check_iid" in body:
        del body["check_iid"]
    if "_id" in body:
        del body["_id"]
    
    mongoInstance.updateInDb(pentest, CheckInstance.coll_name, {"_id": ObjectId(iid), "type":"checkinstance"}, {"$set": body}, False, True)
    return True

@permission("pentester")
def getInformations(pentest, iid):
    inst = CheckInstance.fetchObject(pentest, {"_id": ObjectId(iid)})
    if inst is None:
        return "Not found", 404
    check_item = CheckItem.fetchObject({"_id": ObjectId(inst.check_iid)})
    if check_item is None:
        return "Check item parent not found"
    data = inst.getData()
    check_item_data = check_item.getData()
    data["check_item"] = check_item_data
    data["tools_status"] = {}
    data["tools_not_done"] = {}
    all_complete = True
    at_least_one = False
        
    for command in check_item.commands:
        command_m = ServerCommand.fetchObject({"original_iid": str(command)}, targetdb=pentest)
        
        total = 0  
        done = 0
        tools_to_add = ServerTool.fetchObjects(pentest, {"command_iid": str(command_m.getId())})
        if tools_to_add is not None:
            for tool in tools_to_add:
                if "done" in tool.getStatus():
                    done += 1
                    at_least_one = True
                else:
                    data["tools_not_done"][str(tool.getId())]= tool.getDetailedString()
                total += 1

        if done != total:
            all_complete = False
        data["tools_status"][command_m.name] = {"done":done, "total":total}
    if len(check_item.commands):
        if at_least_one and all_complete:
            data["status"] = "done"
        elif at_least_one and not all_complete:
            data["status"] = "running"
        else:
            data["status"] = "not done"
    else:
        data["status"] = ""
    return data