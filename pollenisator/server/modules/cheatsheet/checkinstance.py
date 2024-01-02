import cProfile
import io
import pstats
import time
from bson import ObjectId
from pollenisator.core.components.mongo import DBClient
from pollenisator.server.servermodels.element import ServerElement
from pollenisator.server.servermodels.tool import ServerTool
from pollenisator.server.servermodels.command import ServerCommand
from pollenisator.server.modules.cheatsheet.cheatsheet import CheckItem
from pollenisator.server.permission import permission
from pollenisator.core.components.utils import checkCommandService
from pollenisator.core.components.logger_config import logger

class CheckInstance(ServerElement):
    coll_name = 'checkinstances'

    
    def __init__(self, pentest, valuesFromDb=None):
        dbclient = DBClient.getInstance()
        if pentest != "":
            self.pentest = pentest
        elif dbclient.current_pentest != "":
            self.pentest = dbclient.current_pentest
        else:
            raise ValueError(
                "An empty pentest name was given and the database is not set in mongo instance.")
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
        elif dbclient.current_pentest != "":
            self.pentest = dbclient.current_pentest
        else:
            raise ValueError(
                "An empty pentest name was given and the database is not set in mongo instance.")
        return self
    
    @classmethod
    def getSearchableTextAttribute(cls):
        return ["title", "category", "lvl"] # will load on checktitems attribute
    
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
    
    def getCheckItem(self):
        return CheckItem.fetchObject({"_id": ObjectId(self.check_iid)})

    def getData(self):
        return {"_id": self._id, "type": self.type, "check_iid": self.check_iid, "target_iid": self.target_iid, "target_type": self.target_type, "parent": self.parent, "status": self.status, "notes": self.notes}

    def addInDb(self, checkItem=None, toolInfos={}):
        ret = doInsert(self.pentest, self.getData(), checkItem, toolInfos)
        return ret
    
    @classmethod
    def bulk_insert_for(cls, pentest, targets, targets_type, lvls, f_get_impacted_targets=None, toolInfos=None):
        dbclient = DBClient.getInstance()
        pentest_type = dbclient.findInDb(pentest, "settings", {"key":"pentest_type"}, False)
        pentest_type = None if pentest_type is None else pentest_type.get("value", None)
        checks = CheckItem.fetchObjects({"lvl":{"$in":lvls}, "pentest_types":pentest_type})
        if checks is None:
            return
        checks_to_add = []
        start = time.time()
        targets = list(targets)
        
        commands_pentest = ServerCommand.fetchObjects({}, pentest)
        commands_lkp = {command_pentest.original_iid: command_pentest for command_pentest in commands_pentest}
        check_command_lkp = {}
        for checkItem in checks:
            if callable(f_get_impacted_targets):
                subset = f_get_impacted_targets(checkItem, targets)
            else:
                subset = targets
            for target in subset:
                checkinstance = CheckInstance(pentest).initialize(pentest, None, str(
                    checkItem._id), str(target.getId()), targets_type, None, "", "")
                checks_to_add.append(checkinstance)
            for command in checkItem.commands:
                check_command_lkp[str(checkItem.getId())] = check_command_lkp.get(str(checkItem.getId()), []) + [commands_lkp.get(command, None)]
        

        if not checks_to_add:
            return
        lkp = {}
        check_keys = set()
        or_conditions = []
        start = time.time()
        for check in checks_to_add:
            hashable_key = check.getHashableDbKey()
            lkp[hashable_key] = check.getData()
            del lkp[hashable_key]["_id"]
            lkp[hashable_key]["type"] = "checkinstance"
            check_keys.add(hashable_key)
            or_conditions.append(check.getDbKey())
        dbclient.create_index(pentest, "checkinstances", [("check_iid", 1), ("target_iid", 1), ("target_type", 1)])
        existing_checks = CheckInstance.fetchObjects(pentest, {"$or": or_conditions})
        existing_checks_as_keys = [] if existing_checks is None else [ existing_check.getHashableDbKey() for existing_check in existing_checks]
        existing_checks_as_keys = set(existing_checks_as_keys)
        to_add = check_keys - existing_checks_as_keys
        things_to_insert = [lkp[check] for check in to_add]
        #UPDATE EXISTING
        # Insert new
        if not things_to_insert:
            return
        res = dbclient.insertInDb(pentest, CheckInstance.coll_name, things_to_insert, multi=True)
        checks_inserted = list(CheckInstance.fetchObjects(pentest, {"_id": {"$in":res.inserted_ids}}))
        # for each commands, add the tool
        tools_to_add = []
        #for checkitem_id, commands in check_command_lkp.items():
        for check in checks_inserted:
            checkitem_id = check.check_iid
            commands = check_command_lkp.get(checkitem_id, [])
            for command in commands:
                tool = ServerTool(pentest)
                targetdata = target.getData()
                tool.initialize(str(command.getId()), str(check.getId()), targetdata.get("wave", ""), command.name, targetdata.get("scope", ""), targetdata.get("ip", ""), targetdata.get("port", ""),
                                            targetdata.get("proto", ""), checkItem.lvl, infos=toolInfos)
                tools_to_add.append(tool)
        if tools_to_add:
            ServerTool.bulk_insert(pentest, tools_to_add)
        
        return checks_inserted
    

    @classmethod
    def bulk_queue(cls, pentest, checks_iids, priority):
        dbclient = DBClient.getInstance()
        results = {"successes":[], "failures":[]}
        queue = dbclient.findInDb(pentest, "autoscan", {"type":"queue"}, False) 
        if queue is None:
            queue = list()
            dbclient.insertInDb(pentest, "autoscan", {"type":"queue", "tools":[]}) 
        else:
            queue = list(queue["tools"])
        index = len(queue)
        for i, tool_info in enumerate(queue):
            if priority > tool_info.get("priority", 0):
                index = i
                break
        tools = dbclient.findInDb(pentest, "tools", {"check_iid":{"$in":checks_iids}, "status":{"$ne":"done"}}, True)
        queue_final = queue[:index] + [{"iid":tool.getId(), "priority":priority} for tool in tools] + queue[index:]
        dbclient.updateInDb(pentest, "autoscan", {"type":"queue"}, {"$set":{"tools":queue_final}})
        return results
                    
    @classmethod
    def createFromCheckItem(cls, pentest, checkItem, target_iid, target_type, infos={}):
        parent = None
        checkinstance = CheckInstance(pentest).initialize(pentest, None, str(
            checkItem._id), str(target_iid), target_type, parent, "", "")
        return checkinstance.addInDb(checkItem=checkItem, toolInfos=infos)

    def update(self):
        return update(self.pentest, self._id, self.getData())
    
    def getDbKey(self):
        return {"check_iid": self.check_iid, "target_iid": self.target_iid, "target_type": self.target_type}
    
    def getHashableDbKey(self):
        return tuple(self.getDbKey().values())
    
    def updateInfos(self, check_item=None):
        if check_item is None:
            check_item = CheckItem.fetchObject({"_id": ObjectId(self.check_iid)})
        if check_item is None:
            return "Check item parent not found"
        data = self.getData()
        check_item_data = check_item.getData()
        data["check_item"] = check_item_data
        data["tools_status"] = {}
        data["tools_not_done"] = {}
        data["tools_error"] = {}
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
                elif "error" in tool.getStatus():
                    data["tools_error"][str(
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
        if data["status"] != "":
            self.status = data["status"]
            self.update()

def doInsert(pentest, data, checkItem=None, toolInfos=None):
    if "_id" in data:
        del data["_id"]
    dbclient = DBClient.getInstance()
    data["type"] = "checkinstance"
    # CHECK EXISTING
    existing = CheckInstance.fetchObject(pentest, {"check_iid": str(data["check_iid"]), "target_iid": data.get(
        "target_iid", ""), "target_type": data.get("target_type", "")})
    if existing is not None:
        return {"res": False, "iid": existing.getId()}
    # IF NOT EXISTING INSERT
    ins_result = dbclient.insertInDb(
        pentest, CheckInstance.coll_name, data, True)
    ins_check = CheckInstance(pentest, data)
    iid = ins_result.inserted_id
    ins_check._id = iid
    if checkItem is None or str(checkItem._id) != str(data["check_iid"]):
        checkItem = CheckItem.fetchObject(
            {"_id": ObjectId(data["check_iid"])})
    
    target_class = ServerElement.classFactory(data["target_type"])
    target = dbclient.findInDb(pentest, target_class.coll_name, {
                                    "_id": ObjectId(data["target_iid"])}, False)
    if target is None:
        return "Invalid target, not found", 404
    if checkItem is None:
        return "Check Item not found", 404
    for command in checkItem.commands:
        command_pentest = ServerCommand.fetchObject({"original_iid": str(command)}, pentest)
        if command_pentest is not None:
            tool = ServerTool(pentest)
            tool.initialize(str(command_pentest._id), str(iid), target.get("wave", ""), None, target.get("scope", ""), target.get("ip", ""), target.get("port", ""),
                                        target.get("proto", ""), checkItem.lvl, infos=toolInfos).addInDb(update_check_infos=False)
            #tool.addToQueue() #TODO : SETTINGS TO ENABLE/DISABLE AUTOSCAN AUTO ADD
    
    if ins_result is None:
        return {"res": False, "iid": iid}
    # else:
    #     ins_check.updateInfos(check_item=checkItem) # TODO CHECK IF WAS USEFUL
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
    return res


@permission("pentester")
def update(pentest, iid, body):
    if pentest == "pollenisator":
        return "Forbidden", 403
    if "_id" in body:
        del body["_id"]
    if "type" in body:
        del body["type"]
    if "check_iid" in body:
        del body["check_iid"]
    checkinstance = CheckInstance(pentest, body)
    dbclient = DBClient.getInstance()
    existing = CheckInstance.fetchObject(pentest, {"_id": ObjectId(iid)})
    if existing is None:
        return "Not found", 404
    dbclient.updateInDb(pentest, CheckInstance.coll_name, {"_id": ObjectId(
        iid), "type": "checkinstance"}, {"$set": body}, many=False, notify=True)
    return True


@permission("pentester")
def getInformations(pentest, iid):
    pr = cProfile.Profile()
    pr.enable()
    inst = CheckInstance.fetchObject(pentest, {"_id": ObjectId(iid)})
    if inst is None:
        return "Not found", 404
    check_item = CheckItem.fetchObject({"_id": ObjectId(inst.check_iid)})
    if check_item is None:
        return "Check item parent not found", 404
    data = inst.getData()
    check_item_data = check_item.getData()
    data["check_item"] = check_item_data
    data["tools_done"] = {}
    data["tools_running"] = {}
    data["tools_not_done"] = {}
    data["tools_error"] = {}
    all_complete = True
    at_least_one = False
    total = 0
    done = 0
    dbclient = DBClient.getInstance()
    dbclient.create_index(pentest, "tools", [("check_iid",1)])
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
            elif "error" in tool.getStatus():
                data["tools_error"][str(
                    tool.getId())] = tool.getData()
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
    pr.disable()
    s = io.StringIO()
    sortby = pstats.SortKey.CUMULATIVE
    ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
    ps.print_stats()
    with open("/tmp/profileserv.txt", "w") as f:
        f.write(s.getvalue())
    return data


@permission("pentester")
def getTargetRepr(pentest, body):
    dbclient = DBClient.getInstance()
    iids_list = [ ObjectId(x) for x in body ]
    checkinstances = dbclient.findInDb(pentest, "checkinstances", {"_id": {"$in": iids_list}}, True)
    ret = {}
    elements = {}
    for data in checkinstances:
        if data["target_type"] not in elements:
            elements[data["target_type"]] = set()
        elements[data["target_type"]].add(ObjectId(data["target_iid"]))
    for element_type, element_iids in elements.items():
        class_element = ServerElement.classFactory(element_type)
        if class_element is not None:
            elems = class_element.fetchObjects(pentest, {"_id": {"$in":list(element_iids)}})
            if not elems:
                ret_str = "Target not found"
            for elem in elems:
                ret_str = elem.getDetailedString()
                ret[str(elem.getId())] = ret_str
    return ret

@permission("pentester")
def multiChangeOfStatus(pentest, body):
    dbclient = DBClient.getInstance()
    iids_list = [ ObjectId(x) for x in body["iids"] ]
    dbclient.updateInDb(pentest, "checkinstances", {"_id": {"$in": iids_list}}, {"$set": {"status": body["status"]}}, many=True, notify=True)

@permission("pentester")
def queueCheckInstances(pentest, body):
    pr = cProfile.Profile()
    pr.enable()
    iids_list = [ ObjectId(x) for x in body.get("iids", []) ]
    check_iids = set()
    for check_iid in iids_list:
        if isinstance(check_iid, str) and check_iid.startswith("ObjectId|"):
            check_iid = check_iid.replace("ObjectId|", "")
        check_iids.add(str(check_iid))
    results = CheckInstance.bulk_queue(pentest, list(check_iids), body.get("priority", 0))
    pr.disable()
    s = io.StringIO()
    sortby = pstats.SortKey.CUMULATIVE
    ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
    ps.print_stats()
    with open("/tmp/profileserv.txt", "w") as f:
        f.write(s.getvalue())
    return results    