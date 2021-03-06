from bson import ObjectId
from core.Components.mongo import MongoCalendar
from netaddr import IPNetwork, IPAddress
from netaddr.core import AddrFormatError
from core.Models.Ip import Ip
from core.Controllers.IpController import IpController
from server.ServerModels.Tool import ServerTool
from server.ServerModels.Tool import delete as tool_delete
from server.ServerModels.Port import ServerPort
from server.ServerModels.Port import delete as port_delete
from server.ServerModels.Defect import delete as defect_delete
from server.ServerModels.Element import ServerElement
from core.Components.Utils import JSONEncoder, performLookUp
from server.permission import permission
import json

mongoInstance = MongoCalendar.getInstance()
class ServerIp(Ip, ServerElement):

    def __init__(self, pentest="", *args, **kwargs):
        if pentest != "":
            self.pentest = pentest
        elif mongoInstance.calendarName != "":
            self.pentest = mongoInstance.calendarName
        else:
            raise ValueError("An empty pentest name was given and the database is not set in mongo instance.")
        mongoInstance.connectToDb(self.pentest)
        super().__init__(*args, **kwargs)


    def initialize(self, ip="", notes="", in_scopes=None, tags=None, infos=None):
        """Set values of ip
        Args:
            ip: the host (ip or domain) to represent
            notes: notes concerning this IP (opt). Default to ""
            in_scopes: a list of scopes that matches this host. If empty this IP will be OOS (Out of Scope). Default to None
            tags: a list of tags. Default to None
            infos: a dictionnary of additional info
        Returns:
            this object
        """
        self.ip = ip
        self.notes = notes
        self.in_scopes = in_scopes if in_scopes is not None else self.getScopesFittingMe()
        self.tags = tags if tags is not None else []
        self.infos = infos if infos is not None else {}
        return self
    
    def getScopesFittingMe(self):
        """Returns a list of scope objects ids where this IP object fits.
        Returns:
            a list of scopes objects Mongo Ids where this IP/Domain is in scope.
        """
        ret = []
        mongoInstance.connectToDb(self.pentest)
        scopes = mongoInstance.find("scopes", {})
        if scopes is None:
            return ret
        for scope in scopes:
            if self.fitInScope(scope["scope"]):
                ret.append(str(scope["_id"]))
        return ret

    @classmethod
    def fetchObjects(cls, pentest, pipeline):
        """Fetch many commands from database and return a Cursor to iterate over model objects
        Args:
            pipeline: a Mongo search pipeline (dict)
        Returns:
            Returns a cursor to iterate on model objects
        """
        mongoInstance.connectToDb(pentest)
        ds = mongoInstance.find(cls.coll_name, pipeline, True)
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
        mongoInstance.connectToDb(pentest)
        ds = mongoInstance.find(cls.coll_name, pipeline, False)
        if ds is None:
            return None
        return cls(pentest, ds) 

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
            update(pentest, self._id, IpController(self).getData())
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
            update(pentest, self._id, IpController(self).getData())


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

    def addInDb(self):
        return insert(self.pentest, IpController(self).getData())

    def update(self):
        return update("ips", self._id, IpController(self).getData())

@permission("pentester")
def delete(pentest, ip_iid):
    mongoInstance.connectToDb(pentest)
    ip_dic = mongoInstance.find("ips", {"_id":ObjectId(ip_iid)}, False)
    if ip_dic is None:
        return 0
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
@permission("pentester")
def insert(pentest, body):
    mongoInstance.connectToDb(pentest)
    ip_o = ServerIp(pentest, body)
    base = ip_o.getDbKey()
    existing = mongoInstance.find(
            "ips", base, False)
    if existing is not None:
        return {"res":False, "iid":existing["_id"]}
    if "_id" in body:
        del body["_id"]
    parent = ip_o.getParentId()
    ins_result = mongoInstance.insert("ips", body, parent)
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

@permission("pentester")
def update(pentest, ip_iid, body):
    mongoInstance.connectToDb(pentest)
    return mongoInstance.update("ips", {"_id":ObjectId(ip_iid)}, {"$set":body}, False, True)

