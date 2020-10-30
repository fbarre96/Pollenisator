from bson import ObjectId
from core.Components.mongo import MongoCalendar
from netaddr import IPNetwork, IPAddress
from netaddr.core import AddrFormatError
from core.Models.Ip import Ip
from core.Controllers.IpController import IpController
from server.ServerModels.Tool import ServerTool
from server.ServerModels.Tool import delete as tool_delete
from server.ServerModels.Port import delete as port_delete
from server.ServerModels.Defect import delete as defect_delete
from core.Components.Utils import JSONEncoder, performLookUp
import json

mongoInstance = MongoCalendar.getInstance()
class ServerIp(Ip):
    def __init__(self, pentest, *args, **kwargs):
        self.pentest = pentest
        super().__init__(*args, **kwargs)

    @classmethod
    def getIpsInScope(cls, pentest, scopeId):
        """Returns a list of IP objects that have the given scope id in there matching scopes.
        Args:
            scopeId: a mongo ObjectId of a scope object.
        Returns:
            a mongo cursor of IP objects matching the given scopeId
        """
        mongoInstance.connectToDb(pentest)
        ips = mongoInstance.find("ips", {"in_scopes": {"$elemMatch": {"$eq": str(scopeId)}}})
        for ip in ips:
            yield ServerIp(pentest, ip)
    
    def removeScopeFitting(self, pentest, scopeId):
        """Remove the given scopeId from the list of scopes this IP fits in.
        Args:
            scopeId: a mongo ObjectId of a scope object.
        """
        if str(scopeId) in self.in_scopes:
            self.in_scopes.remove(str(scopeId))
            update(pentest, self._id, ControllerIp(self).getData())
            if not self.in_scopes:
                tools = ServerTool.fetchObjects(pentest, {"ip": self.ip})
                for tool in tools:
                    tool.setOutOfScope(pentest)

    def addScopeFitting(self, pentest, scopeId):
        """Add the given scopeId to the list of scopes this IP fits in.
        Args:
            scopeId: a mongo ObjectId of a Scope object.
        """
        if not self.in_scopes:
            tools = ServerTool.fetchObjects(pentest, {"ip": self.ip})
            for tool in tools:
                tool.setInScope()
        if str(scopeId) not in self.in_scopes:
            self.in_scopes.append(str(scopeId))
            update(pentest, self._id, ControllerIp(self).getData())


    def getParentId(self):
        if self.parent is not None:
            return self.parent
        try:
            if IPAddress(self.ip).is_private():
                return None
        except AddrFormatError:
            return None
        except ValueError:
            return None
        ip_real = performLookUp(self.ip)
        if ip_real is not None:
            mongoInstance.connectToDb(self.pentest)
            ip_in_db = mongoInstance.find("ips", {"ip": ip_real}, False)
            if ip_in_db is None:
                return None
            self.parent = ip_in_db["_id"]
            update(self.pentest, self._id, {"parent": self.parent})
            return ip_in_db["_id"]
        return None

    def addAllTool(self, command_name, wave_name, scope):
        """
        Kind of recursive operation as it will call the same function in its children ports.
        Add the appropriate tools (level check and wave's commands check) for this ip.
        Also add for all registered ports the appropriate tools.

        Args:
            command_name: The command that we want to create all the tools for.
            wave_name: the wave name from where we want to load tools
            scope: a scope object allowing to launch this command. Opt
        """
        # retrieve the command level
        mongoInstance.connectToDb(self.pentest)
        command = mongoInstance.findInDb(self.pentest,
                                         "commands", {"name": command_name}, False)
        if command["lvl"] == "ip":
            # finally add tool
            newTool = ServerTool(self.pentest)
            newTool.initialize(command_name, wave_name,
                               "", self.ip, "", "", "ip")
            newTool.addInDb()
            return
        # Do the same thing for all children ports.
        ports = mongoInstance.find("ports", {"ip": self.ip})
        for port in ports:
            p = ServerPort(self.pentest, port)
            p.addAllTool(command_name, wave_name, scope)


def delete(pentest, ip_iid):
    mongoInstance.connectToDb(pentest)
    ip_dic = mongoInstance.find("ips", {"_id":ObjectId(ip_iid)}, False)
    tools = mongoInstance.find("tools",
                                {"ip": ip_dic["ip"]}, True)
    for tool in tools:
        tool_delete(pentest, tool["_id"])
    defects = mongoInstance.find("defects",
                                    {"ip": ip_dic["ip"], "$or": [{"port": {"$exists": False}}, {"port": None}]}, True)
    for defect in defects:
        defect_delete(pentest, defect["_id"])
    ports = mongoInstance.find("ports",
                                {"ip": ip_dic["ip"]}, True)
    for port in ports:
        port_delete(pentest, port["_id"])
    res = mongoInstance.delete("ips", {"_id": ObjectId(ip_iid)}, False)
    if res is None:
        return 0
    else:
        return res.deleted_count

def insert(pentest, data):
    mongoInstance.connectToDb(pentest)
    ip_o = ServerIp(pentest, data)
    base = ip_o.getDbKey()
    existing = mongoInstance.find(
            "ips", base, False)
    if existing is not None:
        return {"res":False, "iid":existing["_id"]}
    parent = ip_o.getParentId()
    ins_result = mongoInstance.insert("ips", data, parent)
    iid = ins_result.inserted_id
    waves = mongoInstance.find("waves", {})
    for wave in waves:
        waveName = wave["wave"]
        commands = wave["wave_commands"]
        for commName in commands:
            # 2. finding the command only if lvl is port
            comm = mongoInstance.findInDb(pentest, "commands",
                                            {"name": commName, "lvl": "ip"}, False)
            if comm is not None:
                # 3. checking if the added port fit into the command's allowed service
                # 3.1 first, default the selected port as tcp if no protocole is defined.
                tool_o = ServerTool(pentest)
                tool_o.initialize(comm["name"], waveName, "", ip_o.ip, "", "", "ip")
                tool_o.addInDb()
    return {"res":True, "iid":iid}


def update(pentest, ip_iid, data):
    mongoInstance.connectToDb(pentest)
    return mongoInstance.update("ips", {"_id":ObjectId(ip_iid)}, {"$set":data}, False, True)

