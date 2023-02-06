from bson import ObjectId
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.models.port import Port
from pollenisator.core.controllers.portcontroller import PortController
from pollenisator.server.servermodels.tool import ServerTool, delete as tool_delete
from pollenisator.server.servermodels.defect import delete as defect_delete
from pollenisator.server.modules.activedirectory.computers import (
    insert as computer_insert,
    update as computer_update,
    Computer
)
from pollenisator.server.servermodels.element import ServerElement
from pollenisator.core.components.utils import JSONEncoder, checkCommandService
import json
from pollenisator.server.modules.cheatsheet.cheatsheet import CheckItem
from pollenisator.server.modules.cheatsheet.checkinstance import CheckInstance, delete as checkinstance_delete
from pollenisator.server.permission import permission

class ServerPort(Port, ServerElement):
    
    def __init__(self, pentest="", *args, **kwargs):
        dbclient = DBClient.getInstance()
        if pentest != "":
            self.pentest = pentest
        elif dbclient.pentestName != "":
            self.pentest = dbclient.pentestName
        else:
            raise ValueError("An empty pentest name was given and the database is not set in mongo instance.")
        super().__init__(*args, **kwargs)


    def getParentId(self):
        dbclient = DBClient.getInstance()
        return dbclient.findInDb(self.pentest, "ips", {"ip": self.ip}, False)["_id"]

    def addChecks(self, lvls):
        """
        Add the appropriate checks (level check and wave's commands check) for this scope.
        """
        checkitems = CheckItem.fetchObjects({"lvl": {"$in": lvls}})
        if checkitems is None:
            return
        for check in checkitems:
            allowed_ports_services = check.ports.split(",")
            if checkCommandService(allowed_ports_services, self.port, self.proto, self.service):
                CheckInstance.createFromCheckItem(self.pentest, check, str(self._id), "port")

    @classmethod
    def getTriggers(cls):
        """
        Return the list of trigger declared here
        """
        return ["port:onServiceUpdate"]



    @classmethod
    def replaceCommandVariables(cls, pentest, command, data):
        command = command.replace("|port|", data.get("port", ""))
        command = command.replace("|port.proto|", data.get("proto", ""))
        if data.get("port")  is not None and data.get("ip")  is not None:
            dbclient = DBClient.getInstance()
            port_db = dbclient.findInDb(pentest, "ports", {"port":data.get("port") , "proto":data.get("proto", "tcp") , "ip":data.get("ip") }, False)
            if port_db is not None:
                command = command.replace("|port.service|", port_db.get("service", ""))
                command = command.replace("|port.product|", port_db.get("product",""))
                port_infos = port_db.get("infos", {})
                for info in port_infos:
                    command = command.replace("|port.infos."+str(info)+"|", str(port_infos[info]))
        return command

    @classmethod
    def completeDetailedString(cls, data):
        return data.get("ip", "")+":"+data.get("port", "")+ " "

    def addInDb(self):
        return insert(self.pentest, PortController(self).getData())

    def update(self):
        return update("ports", ObjectId(self._id), PortController(self).getData())

@permission("pentester")
def delete(pentest, port_iid):
    dbclient = DBClient.getInstance()

    port_o = ServerPort(pentest, dbclient.findInDb(pentest, "ports", {"_id":ObjectId(port_iid)}, False))
    tools = dbclient.findInDb(pentest, "tools", {"port": port_o.port, "proto": port_o.proto,
                                             "ip": port_o.ip}, True)
    for tool in tools:
        tool_delete(pentest, tool["_id"])
    checks = dbclient.findInDb(pentest, "cheatsheet",
                                {"target_iid": str(port_iid)}, True)
    for check in checks:
        checkinstance_delete(pentest, check["_id"])
    defects = dbclient.findInDb(pentest, "defects", {"port": port_o.port, "proto": port_o.proto,
                                                "ip": port_o.ip}, True)
    for defect in defects:
        defect_delete(pentest, defect["_id"])
    res = dbclient.deleteFromDb(pentest, "ports", {"_id": ObjectId(port_iid)}, False)
    if res is None:
        return 0
    else:
        return res.deleted_count

@permission("pentester")
def insert(pentest, body):
    dbclient = DBClient.getInstance()
    port_o = ServerPort(pentest, body)
    base = port_o.getDbKey()
    existing = dbclient.findInDb(pentest,
            "ports", base, False)
    if existing is not None:
        return {"res":False, "iid":existing["_id"]}
    if "_id" in body:
        del body["_id"]
    parent = port_o.getParentId()
    ins_result = dbclient.insertInDb(pentest, "ports", body, parent)
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
    port_o.addChecks(["port:onServiceUpdate"])
    return {"res":True, "iid":iid}

@permission("pentester")
def update(pentest, port_iid, body):
    dbclient = DBClient.getInstance()
    
    oldPort = ServerPort(pentest, dbclient.findInDb(pentest, "ports", {"_id": ObjectId(port_iid)}, False))
    if oldPort is None:
        return
    port_o = ServerPort(pentest, body)
    oldService = oldPort.service
    if oldService != port_o.service:
        
        dbclient.deleteFromDb(pentest, "tools", {
                                "lvl": "port:onServiceUpdate", "ip": oldPort.ip, "port": oldPort.port, "proto": oldPort.proto, "status":{"$ne":"done"}}, many=True)
        dbclient.deleteFromDb(pentest, "cheatsheet", {
                                "lvl": "port:onServiceUpdate", "ip": oldPort.ip, "port": oldPort.port, "proto": oldPort.proto, "status":{"$ne":"done"}}, many=True)     
        port_o.addChecks(["port:onServiceUpdate"])
    dbclient.updateInDb(pentest, "ports", {"_id":ObjectId(port_iid)}, {"$set":body}, False, True)
    return True
   