from bson import ObjectId
from core.Components.mongo import MongoCalendar
from core.Models.Scope import Scope
from server.ServerModels.Tool import delete as tool_delete
from server.ServerModels.Tool import ServerTool
from server.ServerModels.Ip import ServerIp
from server.ServerModels.Element import ServerElement
from core.Components.Utils import JSONEncoder, isNetworkIp, performLookUp, isIp
import json

mongoInstance = MongoCalendar.getInstance()

class ServerScope(Scope, ServerElement):
    
    def __init__(self, pentest="", *args, **kwargs):
        super().__init__(*args, **kwargs)
        if pentest != "":
            self.pentest = pentest
        elif mongoInstance.calendarName != "":
            self.pentest = mongoInstance.calendarName
        else:
            raise ValueError("An empty pentest name was given and the database is not set in mongo instance.")
        mongoInstance.connectToDb(self.pentest)

    @classmethod
    def fetchObjects(cls, pentest, pipeline):
        mongoInstance.connectToDb(pentest)
        results = mongoInstance.find("scopes", pipeline)
        for result in results:
            yield(cls(pentest, result))

    def getParentId(self):
        mongoInstance.connectToDb(self.pentest)
        res = mongoInstance.find("waves", {"wave": self.wave}, False)
        return res["_id"]

    def addAllTool(self, command_name):
        """
        Add the appropriate tools (level check and wave's commands check) for this scope.
        Args:
            command_name: The command that we want to create all the tools for.
        """
        mongoInstance.connectToDb(self.pentest)
        command = mongoInstance.findInDb(self.pentest, "commands", {
                                         "name": command_name}, False)
        if command["lvl"] == "network":
            newTool = ServerTool(self.pentest)
            newTool.initialize(
                command["name"], self.wave, self.scope, "", "", "", "network")
            newTool.addInDb()
            return
        if command["lvl"] == "domain":
            if not isNetworkIp(self.scope):
                newTool = ServerTool(self.pentest)
                newTool.initialize(
                    command["name"], self.wave, self.scope, "", "", "", "domain")
                newTool.addInDb()
            return
        ips = self.getIpsFitting()
        for ip in ips:
            i = ServerIp(self.pentest, ip)
            i.addAllTool(command_name, self.wave, self.scope)

    def getIpsFitting(self):
        """Returns a list of ip mongo dict fitting this scope
        Returns:
            A list ip IP dictionnary from mongo db
        """
        mongoInstance.connectToDb(self.pentest)
        ips = mongoInstance.find("ips", )
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

def delete(pentest, scope_iid):
    mongoInstance.connectToDb(pentest)
    # deleting tool with scope lvl
    scope_o = ServerScope(pentest, mongoInstance.find("scopes", {"_id": ObjectId(scope_iid)}, False))
    tools = mongoInstance.find("tools", {"scope": scope_o.scope, "wave": scope_o.wave, "$or": [
                                {"lvl": "network"}, {"lvl": "domain"}]})
    for tool in tools:
        tool_delete(pentest, tool["_id"])
    # Deleting this scope against every ips
    ips = ServerIp.getIpsInScope(pentest, scope_iid)
    for ip in ips:
        ip.removeScopeFitting(pentest, scope_iid)
    res = mongoInstance.delete("scopes", {"_id": ObjectId(scope_iid)}, False)
    parent_wave = mongoInstance.find("waves", {"wave": scope_o.wave}, False)
    if parent_wave is None:
        return
    mongoInstance.notify(pentest,
                            "waves", parent_wave["_id"], "update", "")
    # Finally delete the selected element
    if res is None:
        return 0
    else:
        return res.deleted_count

def insert(pentest, data):
    mongoInstance.connectToDb(pentest)
    scope_o = ServerScope(pentest, data)
    # Checking unicity
    base = scope_o.getDbKey()
    existing = mongoInstance.find("scopes", base, False)
    if existing is not None:
        return {"res":False, "iid":existing["_id"]}
    if "_id" in data:
        del data["_id"]
    # Inserting scope
    parent = scope_o.getParentId()
    res_insert = mongoInstance.insert("scopes", base, parent)
    ret = res_insert.inserted_id
    scope_o._id = ret
    # adding the appropriate tools for this scope.
    wave = mongoInstance.find("waves", {"wave": scope_o.wave}, False)
    commands = wave["wave_commands"]
    for commName in commands:
        if commName.strip() != "":
            scope_o.addAllTool(commName)
    # Testing this scope against every ips
    ips = mongoInstance.find("ips", {})
    for ip in ips:
        ip_o = ServerIp(pentest, ip)
        if scope_o._id not in ip_o.in_scopes:
            if ip_o.fitInScope(scope_o.scope):
                ip_o.addScopeFitting(pentest, scope_o.getId())
    return {"res":True, "iid":ret}


def update(pentest, scope_iid, data):
    mongoInstance.connectToDb(pentest)
    return mongoInstance.update("scopes", {"_id":ObjectId(scope_iid)}, {"$set":data}, False, True)