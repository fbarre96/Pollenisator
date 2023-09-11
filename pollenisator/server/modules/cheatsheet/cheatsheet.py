from bson import ObjectId
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.controllers.commandcontroller import CommandController
from pollenisator.server.servermodels.command import ServerCommand
from pollenisator.server.servermodels.command import doInsert as commandDoInsert
from pollenisator.server.servermodels.element import ServerElement
from pollenisator.server.permission import permission
from pollenisator.core.components.utils import JSONDecoder
import json


class CheckItem(ServerElement):
    coll_name = 'cheatsheet'
    def __init__(self, pentest, valuesFromDb=None):
        dbclient = DBClient.getInstance()
        if pentest != "":
            self.pentest = pentest
        elif dbclient.current_pentest != "":
            self.pentest = dbclient.current_pentest
        else:
            raise ValueError("An empty pentest name was given and the database is not set in mongo instance.")
        if valuesFromDb is None:
            valuesFromDb = {}
        if valuesFromDb is None:
            valuesFromDb = {}
        self.initialize(pentest, valuesFromDb.get("_id"), valuesFromDb.get("title"),  valuesFromDb.get("pentest_types"), 
                        valuesFromDb.get("lvl"), valuesFromDb.get("ports"), valuesFromDb.get("priority"), valuesFromDb.get("max_thread"), valuesFromDb.get("description"), valuesFromDb.get("category"),
            valuesFromDb.get("check_type"), valuesFromDb.get("step"), valuesFromDb.get("parent"), 
            valuesFromDb.get("commands"), valuesFromDb.get(""), valuesFromDb.get("defects"), valuesFromDb.get("infos"))
        

    def initialize(self, pentest, _id, title, pentest_types=None, lvl="", ports="", priority=0, max_thread=1, description="", category="", check_type="manual", step=1, parent=None, commands=None, script=None, defects=None, infos=None):

        self._id = _id
        self.type = "checkitem"
        self.title = title
        self.ports = ports
        self.lvl = lvl
        self.description = description
        self.category = category
        self.check_type = check_type
        self.priority = priority
        self.max_thread = max_thread
        self.step = step
        self.parent = parent
        self.commands = [] if commands is None else commands
        self.script = script
        self.pentest_types = [] if pentest_types is None else pentest_types
        self.defects = [] if defects is None else defects
        self.infos = {} if infos is None else infos
        dbclient = DBClient.getInstance()
        if pentest != "":
            self.pentest = pentest
        elif dbclient.current_pentest != "":
            self.pentest = dbclient.current_pentest
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
        dbclient = DBClient.getInstance()
        pipeline["type"] = "checkitem"
        ds = dbclient.findInDb("pollenisator", cls.coll_name, pipeline, True)
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
        dbclient = DBClient.getInstance()
        pipeline["type"] = "checkitem"
        d = dbclient.findInDb("pollenisator", cls.coll_name, pipeline, False)
        if d is None:
            return None
        return cls("pollenisator", d)
  
    def getData(self):
        return {"_id": self._id, "type":self.type, "title":self.title,"pentest_types":self.pentest_types, "lvl":self.lvl, "ports":self.ports,
                "priority":self.priority, "max_thread":self.max_thread, "description": self.description, "category":self.category,
                "check_type":self.check_type, "step":self.step, "parent":self.parent,
                "commands":self.commands, "script":self.script, "defects":self.defects, "infos":self.infos}

    def addInDb(self):
        return doInsert(self.pentest, self.getData())
    

    def apply_retroactively(self, pentest):
        class_registered = ServerElement.getClassWithTrigger(self.lvl)
        if class_registered is None:
            return
        all_objects = class_registered.fetchObjects(pentest, {})
        for obj in all_objects:
            obj.checkAllTriggers()




def doInsert(pentest, data):
    """Insert a checkitem into the database.

    Args:
        pentest: The pentest name.
        data: The data to insert.

    Return:
        A dictionary with the result of the insertion.
    """
    if "_id" in data:
        del data["_id"]
    dbclient = DBClient.getInstance()
    data["type"] = "checkitem"
    existing = CheckItem.fetchObject({"title":data["title"]})
    if existing is not None:
        return {"res":False, "iid":existing.getId()}
    
    ins_result = dbclient.insertInDb(
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
    dbclient = DBClient.getInstance()
    existing = CheckItem.fetchObject({"_id":ObjectId(iid)})
    if existing is None:
        return "Not found", 404
    pentests = dbclient.listPentestUuids()
    for pentest in pentests:
        dbclient.deleteFromDb(pentest, CheckItem.coll_name, {"check_iid":ObjectId(iid)}, many=True, notify=True)
    res = dbclient.deleteFromDb("pollenisator", CheckItem.coll_name, {"_id":ObjectId(iid)}, many=False, notify=True)
    if res is None:
        return 0
    return res.deleted_count

@permission("user")
def update(iid, body):
    # Check if the checkitem to update exists
    existing = CheckItem.fetchObject({"_id": ObjectId(iid)})
    if existing is None:
        return "Not found", 404
    # Check if the title of the checkitem to update is the same as the one provided in the body
    checkitem = CheckItem("pollenisator", body)
    if checkitem.title != existing.title:
        return "Forbidden", 403
    # Remove the type and _id from the body because they can't be updated
    if "type" in body:
        del body["type"]
    if "_id" in body:
        del body["_id"]
    # Update the checkitem
    dbclient = DBClient.getInstance()
    dbclient.updateInDb("pollenisator", CheckItem.coll_name, {"_id": ObjectId(iid), "type":"checkitem"}, {"$set": body}, False, True)
    return True


@permission("user")
def find(body):
    pipeline = body.get("pipeline", {})
    if isinstance(pipeline, str):
        pipeline = json.loads(pipeline, cls=JSONDecoder)
    many = body.get("many", True)
    dbclient = DBClient.getInstance()
    results = dbclient.findInDb("pollenisator", "cheatsheet", pipeline, many)
    if results is None:
        return [] if many else ("Not found", 404)
    if many:
        return [x for x in results]
    return results

@permission("pentester")
def applyToPentest(pentest, iid, body, **kwargs):
    user = kwargs["token_info"]["sub"]
    dbclient = DBClient.getInstance()
    check_item = CheckItem.fetchObject({"_id":ObjectId(iid)})
    if check_item is None:
        return "Not found", 404
    for command in check_item.commands:
        pentest_equiv_command = ServerCommand.fetchObject({"original_iid":str(command)}, pentest)
        if pentest_equiv_command is None:
            orig = ServerCommand.fetchObject({"_id":ObjectId(command)})
            if orig:
                mycommand =  CommandController(orig).getData()
                mycommand["original_iid"] = str(mycommand["_id"])
                mycommand["_id"] = None
                mycommand["indb"] = pentest
                res = commandDoInsert(pentest, mycommand, user)
    check_item.apply_retroactively(pentest)
    return {"res": True}