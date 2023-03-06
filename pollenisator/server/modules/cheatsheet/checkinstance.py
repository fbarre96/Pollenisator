from bson import ObjectId
from pollenisator.core.components.mongo import DBClient
from pollenisator.server.servermodels.element import ServerElement
from pollenisator.server.servermodels.tool import ServerTool
from pollenisator.server.servermodels.command import ServerCommand
from pollenisator.server.modules.cheatsheet.cheatsheet import CheckItem
from pollenisator.server.permission import permission


class CheckInstance(ServerElement):
    coll_name = 'cheatsheet'

    
    def __init__(self, pentest, valuesFromDb=None):
        dbclient = DBClient.getInstance()
        if pentest != "":
            self.pentest = pentest
        elif dbclient.pentestName != "":
            self.pentest = dbclient.pentestName
        else:
            raise ValueError(
                "An empty pentest name was given and the database is not set in mongo instance.")
        if valuesFromDb is None:
            valuesFromDb = {}
        if valuesFromDb is None:
            valuesFromDb = {}
        self.initialize(pentest, valuesFromDb.get("_id"), valuesFromDb.get("check_iid"), valuesFromDb.get("target_iid"), valuesFromDb.get(
            "target_type"), valuesFromDb.get("parent", None), valuesFromDb.get("status", ""), valuesFromDb.get("notes", ""))
        

    def initialize(self, pentest, _id, check_iid, target_iid, target_type, parent, status, notes):
        self._id = _id
        self.parent = parent
        self.type = "checkinstance"
        self.check_iid = check_iid
        self.target_iid = target_iid
        self.target_type = target_type
        self.status = status
        self.notes = notes
        dbclient = DBClient.getInstance()
        if pentest != "":
            self.pentest = pentest
        elif dbclient.pentestName != "":
            self.pentest = dbclient.pentestName
        else:
            raise ValueError(
                "An empty pentest name was given and the database is not set in mongo instance.")
        return self

    @classmethod
    def fetchObjects(cls, pentest, pipeline):
        """Fetch many commands from database and return a Cursor to iterate over model objects
        Args:
            pipeline: a Mongo search pipeline (dict)
        Returns:
            Returns a cursor to iterate on model objects
        """
        dbclient = DBClient.getInstance()
        pipeline["type"] = "checkinstance"
        ds = dbclient.findInDb(pentest, cls.coll_name, pipeline, True)
        if ds is None:
            return None
        for d in ds:
            # disabling this error as it is an abstract function
            yield cls(pentest, d)  #  pylint: disable=no-value-for-parameter

    @classmethod
    def fetchObject(cls, pentest, pipeline):
        """Fetch many commands from database and return a Cursor to iterate over model objects
        Args:
            pipeline: a Mongo search pipeline (dict)
        Returns:
            Returns a cursor to iterate on model objects
        """
        dbclient = DBClient.getInstance()
        pipeline["type"] = "checkinstance"
        d = dbclient.findInDb(pentest, cls.coll_name, pipeline, False)
        if d is None:
            return None
        return cls(pentest, d)

    def getTargetData(self):
        target_class = ServerElement.classFactory(self.target_type)
        dbclient = DBClient.getInstance()
        return dbclient.findInDb(self.pentest, target_class.coll_name, {
                                        "_id": ObjectId(self.target_iid)}, False)

    def getData(self):
        return {"_id": self._id, "type": self.type, "check_iid": self.check_iid, "target_iid": self.target_iid, "target_type": self.target_type, "parent": self.parent, "status": self.status, "notes": self.notes}

    def addInDb(self, checkItem=None, toolInfos={}):
        return doInsert(self.pentest, self.getData(), checkItem, toolInfos)

    @classmethod
    def createFromCheckItem(cls, pentest, checkItem, target_iid, target_type, infos={}):
        parent = None
        if checkItem.parent is not None:
            check_instance_parent = cls.fetchObject(
                pentest, {"check_iid": str(checkItem.parent)})
            parent = str(check_instance_parent.getId())
        checkinstance = CheckInstance(pentest).initialize(pentest, None, str(
            checkItem._id), str(target_iid), target_type, parent, "", "")
        return checkinstance.addInDb(checkItem=checkItem, toolInfos=infos)

    def update(self):
        return update(self.pentest, self._id, self.getData())
    
    
    def updateInfos(self):
        check_item = CheckItem.fetchObject({"_id": ObjectId(self.check_iid)})
        if check_item is None:
            return "Check item parent not found"
        data = self.getData()
        check_item_data = check_item.getData()
        data["check_item"] = check_item_data
        data["tools_status"] = {}
        data["tools_not_done"] = {}
        all_complete = True
        at_least_one = False
        total = 0
        done = 0
        tools_to_add = ServerTool.fetchObjects(self.pentest, {"check_iid": str(self._id)})
        if tools_to_add is not None:
            for tool in tools_to_add:
                if "done" in tool.getStatus():
                    done += 1
                    at_least_one = True
                elif "running" in tool.getStatus():
                    at_least_one = True
                else:
                    data["tools_not_done"][str(
                        tool.getId())] = tool.getDetailedString()
                total += 1

        if done != total:
            all_complete = False
        if len(check_item.commands) > 0:
            if at_least_one and all_complete:
                data["status"] = "done"
            elif at_least_one and not all_complete:
                data["status"] = "running"
            else:
                data["status"] = "todo"
        else:
            data["status"] = ""
        if data["status"] != "":
            self.status = data["status"]
            self.update()

def doInsert(pentest, data, checkItem=None, toolInfos=None):
    if "_id" in data:
        del data["_id"]
    dbclient = DBClient.getInstance()
    data["type"] = "checkinstance"
    existing = CheckInstance.fetchObject(pentest, {"check_iid": str(data["check_iid"]), "target_iid": data.get(
        "target_iid", ""), "target_type": data.get("target_type", "")})
    if existing is not None:
        return {"res": False, "iid": existing.getId()}
    ins_result = dbclient.insertInDb(
        pentest, CheckInstance.coll_name, data, True)
    iid = ins_result.inserted_id
    if checkItem is None or str(checkItem._id) != str(data["check_iid"]):
        checkItem = CheckItem.fetchObject(
            {"_id": ObjectId(data["check_iid"])})
    
    target_class = ServerElement.classFactory(data["target_type"])
    target = dbclient.findInDb(pentest, target_class.coll_name, {
                                    "_id": ObjectId(data["target_iid"])}, False)
    if target is None:
        return "Invalid target not found", 404
    if checkItem is None:
        return "Check Item not found", 404
    for command in checkItem.commands:
        command_pentest = ServerCommand.fetchObject({"original_iid": str(command)}, pentest)
        if command_pentest is not None:
            ServerTool(pentest).initialize(str(command_pentest._id), str(iid), target.get("wave", ""), None, target.get("scope", ""), target.get("ip", ""), target.get("port", ""),
                                        target.get("proto", ""), checkItem.lvl, infos=toolInfos).addInDb()

    return {"res": True, "iid": iid}
    



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
    dbclient = DBClient.getInstance()
    if pentest == "pollenisator":
        return "Forbidden", 403
    existing = CheckInstance.fetchObject(pentest, {"_id": ObjectId(iid)})
    if existing is None:
        return "Not found", 404
    # delete tools
    dbclient.deleteFromDb(
        pentest, 'tools', {"check_iid": ObjectId(iid)}, many=True, notify=True)

    res = dbclient.deleteFromDb(pentest, CheckInstance.coll_name, {
                                     "_id": ObjectId(iid)}, many=False, notify=True)
    if res is None:
        return 0
    return res.deleted_count


@permission("pentester")
def update(pentest, iid, body):
    if pentest == "pollenisator":
        return "Forbidden", 403
    checkinstance = CheckInstance(pentest, body)
    dbclient = DBClient.getInstance()
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

    dbclient.updateInDb(pentest, CheckInstance.coll_name, {"_id": ObjectId(
        iid), "type": "checkinstance"}, {"$set": body}, many=False, notify=True)
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
    data["tools_done"] = {}
    data["tools_running"] = {}
    data["tools_not_done"] = {}
    all_complete = True
    at_least_one = False
    total = 0
    done = 0
    tools_to_add = ServerTool.fetchObjects(pentest, {"check_iid": str(iid)})
    if tools_to_add is not None:
        for tool in tools_to_add:
            if "done" in tool.getStatus():
                done += 1
                at_least_one = True
                data["tools_done"][str(tool.getId())] = tool.getData()
            elif "running" in tool.getStatus():
                at_least_one = True
                data["tools_running"][str(
                    tool.getId())] = tool.getDetailedString()
            else:
                data["tools_not_done"][str(
                    tool.getId())] = tool.getDetailedString()
            total += 1

    if done != total:
        all_complete = False
    if len(check_item.commands) > 0:
        if at_least_one and all_complete:
            data["status"] = "done"
        elif at_least_one and not all_complete:
            data["status"] = "running"
        else:
            data["status"] = "todo"
    else:
        data["status"] = ""
    return data


@permission("pentester")
def getTargetRepr(pentest, body):
    dbclient = DBClient.getInstance()
    iids_list = [ ObjectId(x) for x in body ]
    checkinstances = dbclient.findInDb(pentest, "cheatsheet", {"_id": {"$in": iids_list}}, True)
    ret = {}
    for data in checkinstances:
        class_element = ServerElement.classFactory(data["target_type"])
        elem = class_element.fetchObject(pentest, {"_id": ObjectId(data["target_iid"])})
        if elem is None:
            ret_str = "Target not found"
        else:
            ret_str = elem.getDetailedString()
        ret[str(data["_id"])] = ret_str
    return ret
