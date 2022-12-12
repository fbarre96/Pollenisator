from bson import ObjectId
from pollenisator.core.Components.mongo import MongoCalendar
from pollenisator.core.Models.Scope import Scope
from pollenisator.server.ServerModels.Tool import delete as tool_delete
from pollenisator.server.ServerModels.Tool import ServerTool
from pollenisator.server.ServerModels.Ip import ServerIp
from pollenisator.server.ServerModels.Element import ServerElement
from pollenisator.core.Controllers.ScopeController import ScopeController
from pollenisator.core.Components.Utils import JSONEncoder, isNetworkIp, performLookUp, isIp
import json
from pollenisator.server.permission import permission

class ServerScope(Scope, ServerElement):
    
    def __init__(self, pentest="", *args, **kwargs):
        mongoInstance = MongoCalendar.getInstance()
        super().__init__(*args, **kwargs)
        if pentest != "":
            self.pentest = pentest
        elif mongoInstance.calendarName != "":
            self.pentest = mongoInstance.calendarName
        else:
            raise ValueError("An empty pentest name was given and the database is not set in mongo instance.")

    @classmethod
    def fetchObjects(cls, pentest, pipeline):
        mongoInstance = MongoCalendar.getInstance()
        results = mongoInstance.findInDb(pentest, "scopes", pipeline)
        for result in results:
            yield(cls(pentest, result))

    def getParentId(self):
        mongoInstance = MongoCalendar.getInstance()
        res = mongoInstance.findInDb(self.pentest, "waves", {"wave": self.wave}, False)
        return res["_id"]

    def addInDb(self):
        return insert(self.pentest, ScopeController(self).getData())

    def addAllTool(self, command_iid):
        """
        Add the appropriate tools (level check and wave's commands check) for this scope.
        Args:
            command_name: The command that we want to create all the tools for.
        """
        mongoInstance = MongoCalendar.getInstance()
        command = mongoInstance.findInDb(self.pentest, "commands", {
                                         "_id": ObjectId(command_iid)}, False)
        if command is None:
            return
        if command["lvl"] == "network":
            newTool = ServerTool(self.pentest)
            newTool.initialize(
                command_iid, self.wave, None, self.scope, "", "", "", "network")
            newTool.addInDb()
            return
        if command["lvl"] == "domain":
            if not isNetworkIp(self.scope):
                newTool = ServerTool(self.pentest)
                newTool.initialize(
                    command_iid, self.wave, None, self.scope, "", "", "", "domain")
                newTool.addInDb()
            return
        ips = self.getIpsFitting()
        for ip in ips:
            i = ServerIp(self.pentest, ip)
            i.addAllTool(command_iid, self.wave, self.scope)

    def getIpsFitting(self):
        """Returns a list of ip mongo dict fitting this scope
        Returns:
            A list ip IP dictionnary from mongo db
        """
        mongoInstance = MongoCalendar.getInstance()
        ips = mongoInstance.findInDb(self.pentest, "ips", )
        ips_fitting = []
        isdomain = self.isDomain()
        for ip in ips:
            if isdomain:
                my_ip = performLookUp(self.scope)
                my_domain = self.scope
                ip_isdomain = not isIp(ip["ip"])
                if ip_isdomain:
                    if my_domain == ip["ip"]:
                        ips_fitting.append(ip)
                    if ServerScope.isSubDomain(my_domain, ip["ip"]):
                        ips_fitting.append(ip)
                else:
                    if my_ip == ip["ip"]:
                        ips_fitting.append(ip)
            else:
                if ServerIp.checkIpScope(self.scope, ip["ip"]):
                    ips_fitting.append(ip)
        return ips_fitting
@permission("pentester")
def delete(pentest, scope_iid):
    mongoInstance = MongoCalendar.getInstance()
    # deleting tool with scope lvl
    scope_o = ServerScope(pentest, mongoInstance.findInDb(pentest, "scopes", {"_id": ObjectId(scope_iid)}, False))
    tools = mongoInstance.findInDb(pentest, "tools", {"scope": scope_o.scope, "wave": scope_o.wave, "$or": [
                                {"lvl": "network"}, {"lvl": "domain"}]})
    for tool in tools:
        tool_delete(pentest, tool["_id"])
    # Deleting this scope against every ips
    ips = ServerIp.getIpsInScope(pentest, scope_iid)
    for ip in ips:
        ip.removeScopeFitting(pentest, scope_iid)
    res = mongoInstance.deleteFromDb(pentest, "scopes", {"_id": ObjectId(scope_iid)}, False)
    parent_wave = mongoInstance.findInDb(pentest, "waves", {"wave": scope_o.wave}, False)
    if parent_wave is None:
        return
    mongoInstance.notify(pentest,
                            "waves", parent_wave["_id"], "update", "")
    # Finally delete the selected element
    if res is None:
        return 0
    else:
        return res.deleted_count
        
@permission("pentester")
def insert(pentest, body):
    mongoInstance = MongoCalendar.getInstance()
    scope_o = ServerScope(pentest, body)
    # Checking unicity
    base = scope_o.getDbKey()
    existing = mongoInstance.findInDb(pentest, "scopes", base, False)
    if existing is not None:
        return {"res":False, "iid":existing["_id"]}
    if "_id" in body:
        del body["_id"]
    # Inserting scope
    parent = scope_o.getParentId()
    res_insert = mongoInstance.insertInDb(pentest, "scopes", base, parent)
    ret = res_insert.inserted_id
    scope_o._id = ret
    # adding the appropriate tools for this scope.
    wave = mongoInstance.findInDb(pentest, "waves", {"wave": scope_o.wave}, False)
    commands = wave["wave_commands"]
    for comm_iid in commands:
        scope_o.addAllTool(comm_iid)
    # Testing this scope against every ips
    ips = mongoInstance.findInDb(pentest, "ips", {})
    for ip in ips:
        ip_o = ServerIp(pentest, ip)
        if scope_o._id not in ip_o.in_scopes:
            if ip_o.fitInScope(scope_o.scope):
                ip_o.addScopeFitting(pentest, scope_o.getId())
    return {"res":True, "iid":ret}

@permission("pentester")
def update(pentest, scope_iid, body):
    mongoInstance = MongoCalendar.getInstance()
    mongoInstance.updateInDb(pentest, "scopes", {"_id":ObjectId(scope_iid)}, {"$set":body}, False, True)
    return True