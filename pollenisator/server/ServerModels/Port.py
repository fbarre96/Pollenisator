from bson import ObjectId
from pollenisator.core.Components.mongo import MongoCalendar
from pollenisator.core.Models.Port import Port
from pollenisator.core.Controllers.PortController import PortController
from pollenisator.server.ServerModels.Tool import ServerTool, delete as tool_delete
from pollenisator.server.ServerModels.Defect import delete as defect_delete
from pollenisator.server.modules.ActiveDirectory.computers import (
    insert as computer_insert,
    update as computer_update,
    Computer
)
from pollenisator.server.ServerModels.Element import ServerElement
from pollenisator.core.Components.Utils import JSONEncoder, checkCommandService
import json
from pollenisator.server.modules.Cheatsheet.cheatsheet import CheckItem
from pollenisator.server.modules.Cheatsheet.checkinstance import CheckInstance, delete as checkinstance_delete
from pollenisator.server.permission import permission

class ServerPort(Port, ServerElement):
    
    def __init__(self, pentest="", *args, **kwargs):
        mongoInstance = MongoCalendar.getInstance()
        if pentest != "":
            self.pentest = pentest
        elif mongoInstance.calendarName != "":
            self.pentest = mongoInstance.calendarName
        else:
            raise ValueError("An empty pentest name was given and the database is not set in mongo instance.")
        super().__init__(*args, **kwargs)


    def getParentId(self):
        mongoInstance = MongoCalendar.getInstance()
        return mongoInstance.findInDb(self.pentest, "ips", {"ip": self.ip}, False)["_id"]

    def addAllChecks(self):
        """
        Add the appropriate checks (level check and wave's commands check) for this scope.
        """
        # query mongo db commands collection for all commands having lvl == network or domain
        checkitems = CheckItem.fetchObjects({"lvl": {"$in": ["port"]}})
        if checkitems is None:
            return
        for check in checkitems:
            allowed_ports_services = check.ports.split(",")
            if checkCommandService(allowed_ports_services, self.port, self.proto, self.service):
                CheckInstance.createFromCheckItem(self.pentest, check, str(self._id), "ports")

    
    @classmethod
    def fetchObjects(cls, pentest, pipeline):
        """Fetch many commands from database and return a Cursor to iterate over model objects
        Args:
            pipeline: a Mongo search pipeline (dict)
        Returns:
            Returns a cursor to iterate on model objects
        """
        mongoInstance = MongoCalendar.getInstance()
        ds = mongoInstance.findInDb(pentest, cls.coll_name, pipeline, True)
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
        mongoInstance = MongoCalendar.getInstance()
        d = mongoInstance.findInDb(pentest, cls.coll_name, pipeline, False)
        if d is None:
            return None
        return cls(pentest, d) 

    def addInDb(self):
        return insert(self.pentest, PortController(self).getData())

    def update(self):
        return update("ports", ObjectId(self._id), PortController(self).getData())

@permission("pentester")
def delete(pentest, port_iid):
    mongoInstance = MongoCalendar.getInstance()

    port_o = ServerPort(pentest, mongoInstance.findInDb(pentest, "ports", {"_id":ObjectId(port_iid)}, False))
    tools = mongoInstance.findInDb(pentest, "tools", {"port": port_o.port, "proto": port_o.proto,
                                             "ip": port_o.ip}, True)
    for tool in tools:
        tool_delete(pentest, tool["_id"])
    checks = mongoInstance.findInDb(pentest, "cheatsheet",
                                {"target_iid": str(port_iid)}, True)
    for check in checks:
        checkinstance_delete(pentest, check["_id"])
    defects = mongoInstance.findInDb(pentest, "defects", {"port": port_o.port, "proto": port_o.proto,
                                                "ip": port_o.ip}, True)
    for defect in defects:
        defect_delete(pentest, defect["_id"])
    res = mongoInstance.deleteFromDb(pentest, "ports", {"_id": ObjectId(port_iid)}, False)
    if res is None:
        return 0
    else:
        return res.deleted_count

@permission("pentester")
def insert(pentest, body):
    mongoInstance = MongoCalendar.getInstance()
    port_o = ServerPort(pentest, body)
    base = port_o.getDbKey()
    existing = mongoInstance.findInDb(pentest,
            "ports", base, False)
    if existing is not None:
        return {"res":False, "iid":existing["_id"]}
    if "_id" in body:
        del body["_id"]
    parent = port_o.getParentId()
    ins_result = mongoInstance.insertInDb(pentest, "ports", body, parent)
    iid = ins_result.inserted_id
    port_o._id = iid
    if int(port_o.port) == 445:
        computer_insert(pentest, {"name":"", "ip":port_o.ip, "domain":"", "admins":[], "users":[], "infos":{"is_dc":False}})
    elif int(port_o.port) == 88:
        res = computer_insert(pentest, {"name":"", "ip":port_o.ip, "domain":"", "admins":[], "users":[], "infos":{"is_dc":True}})
        if not res["res"]:
            comp = Computer.fetchObject(pentest, {"_id":ObjectId(res["iid"])})
            comp.infos.is_dc = True
            comp.update()
    port_o.addAllChecks()
    return {"res":True, "iid":iid}

@permission("pentester")
def update(pentest, port_iid, body):
    mongoInstance = MongoCalendar.getInstance()
    
    oldPort = ServerPort(pentest, mongoInstance.findInDb(pentest, "ports", {"_id": ObjectId(port_iid)}, False))
    if oldPort is None:
        return
    port_o = ServerPort(pentest, body)
    oldService = oldPort.service
    if oldService != port_o.service:
        mongoInstance.deleteFromDb(pentest, "tools", {
                                "lvl": "port", "ip": oldPort.ip, "port": oldPort.port, "proto": oldPort.proto, "status":{"$ne":"done"}}, many=True)
        port_commands = mongoInstance.findInDb(
            pentest, "commands", {"lvl": "port"})
        for port_command in port_commands:
            allowed_services = port_command["ports"].split(",")
            for i, elem in enumerate(allowed_services):
                if not(elem.strip().startswith("tcp/") or elem.strip().startswith("udp/")):
                    allowed_services[i] = "tcp/"+str(elem)
            if port_o.proto+"/"+str(port_o.service) in allowed_services:
                waves = mongoInstance.findInDb(pentest, "waves", {"wave_commands": {"$elemMatch": {
                    "$eq": str(port_command["_id"]).strip()}}})
                for wave in waves:
                    tool_m = ServerTool(pentest).initialize(port_command["_id"], wave["wave"], None, "",
                                                oldPort.ip, oldPort.port, oldPort.proto, "port")
                    tool_m.addInDb(check=False) # already checked and not updated yet so service would be wrong
    mongoInstance.updateInDb(pentest, "ports", {"_id":ObjectId(port_iid)}, {"$set":body}, False, True)
    return True
    
# @permission("pentester")
# def addCustomTool(pentest, port_iid, body):
#     mongoInstance = MongoCalendar.getInstance()
#     if not mongoInstance.isUserConnected():
#         return "Not connected", 503
#     if mongoInstance.findInDb(pentest, "waves", {"wave": 'Custom Tools'}, False) is None:
#         mongoInstance.insertInDb(pentest, "waves", {"wave": 'Custom Tools', "wave_commands": list()})
#     port_o = ServerPort(pentest, mongoInstance.findInDb(pentest, "ports", {"_id":ObjectId(port_iid)}, False))
#     port_o.addAllTool(body["command_iid"], 'Custom Tools', '', check=False)
#     return "Success", 200