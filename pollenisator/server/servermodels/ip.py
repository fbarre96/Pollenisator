from bson import ObjectId
from pollenisator.core.components.mongo import MongoClient
from netaddr import IPNetwork, IPAddress
from netaddr.core import AddrFormatError
from pollenisator.core.models.ip import Ip
from pollenisator.core.controllers.ipcontroller import IpController
from pollenisator.server.servermodels.tool import ServerTool
from pollenisator.server.servermodels.tool import delete as tool_delete
from pollenisator.server.servermodels.port import ServerPort
from pollenisator.server.servermodels.port import delete as port_delete
from pollenisator.server.servermodels.defect import delete as defect_delete
from pollenisator.server.servermodels.element import ServerElement
from pollenisator.core.components.utils import JSONEncoder, performLookUp
from pollenisator.server.modules.cheatsheet.cheatsheet import CheckItem
from pollenisator.server.modules.cheatsheet.checkinstance import CheckInstance, delete as checkinstance_delete
from pollenisator.server.permission import permission
import json


class ServerIp(Ip, ServerElement):

    def __init__(self, pentest="", *args, **kwargs):
        mongoInstance = MongoClient.getInstance()
        if pentest != "":
            self.pentest = pentest
        elif mongoInstance.pentestName != "":
            self.pentest = mongoInstance.pentestName
        else:
            raise ValueError("An empty pentest name was given and the database is not set in mongo instance.")
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
        mongoInstance = MongoClient.getInstance()
        scopes = mongoInstance.findInDb(self.pentest, "scopes", {})
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
        mongoInstance = MongoClient.getInstance()
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
        mongoInstance = MongoClient.getInstance()
        ds = mongoInstance.findInDb(pentest, cls.coll_name, pipeline, False)
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
        mongoInstance = MongoClient.getInstance()
        ips = mongoInstance.findInDb(pentest, "ips", {"in_scopes": {"$elemMatch": {"$eq": str(scopeId)}}})
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
            mongoInstance = MongoClient.getInstance()
            ip_in_db = mongoInstance.findInDb(self.pentest, "ips", {"ip": ip_real}, False)
            if ip_in_db is None:
                return None
            self.parent = ip_in_db["_id"]
            update(self.pentest, self._id, {"parent": self.parent})
            return ip_in_db["_id"]
        return None

    def addAllChecks(self):
        """
        Add the appropriate checks (level check and wave's commands check) for this scope.
        """
        # query mongo db commands collection for all commands having lvl == network or domain
        checkitems = CheckItem.fetchObjects({"lvl": {"$in": ["ip"]}})
        if checkitems is None:
            return
        for check in checkitems:
            CheckInstance.createFromCheckItem(self.pentest, check, str(self._id), "ips")
    

    def addInDb(self):
        return insert(self.pentest, IpController(self).getData())

    def update(self):
        return update("ips", self._id, IpController(self).getData())

@permission("pentester")
def delete(pentest, ip_iid):
    mongoInstance = MongoClient.getInstance()
    ip_dic = mongoInstance.findInDb(pentest, "ips", {"_id":ObjectId(ip_iid)}, False)
    if ip_dic is None:
        return 0
    tools = mongoInstance.findInDb(pentest, "tools",
                                {"ip": ip_dic["ip"]}, True)
    for tool in tools:
        tool_delete(pentest, tool["_id"])
    checks = mongoInstance.findInDb(pentest, "cheatsheet",
                                {"target_iid": str(ip_iid)}, True)
    for check in checks:
        checkinstance_delete(pentest, check["_id"])
    defects = mongoInstance.findInDb(pentest, "defects",
                                    {"ip": ip_dic["ip"], "$or": [{"port": {"$exists": False}}, {"port": None}]}, True)
    for defect in defects:
        defect_delete(pentest, defect["_id"])
    ports = mongoInstance.findInDb(pentest, "ports",
                                {"ip": ip_dic["ip"]}, True)
    for port in ports:
        port_delete(pentest, port["_id"])
    res = mongoInstance.deleteFromDb(pentest, "ips", {"_id": ObjectId(ip_iid)}, False)
    if res is None:
        return 0
    else:
        return res.deleted_count

@permission("pentester")
def insert(pentest, body):
    mongoInstance = MongoClient.getInstance()
    ip_o = ServerIp(pentest, body)
    base = ip_o.getDbKey()
    existing = mongoInstance.findInDb(pentest, 
            "ips", base, False)
    if existing is not None:
        return {"res":False, "iid":existing["_id"]}
    if "_id" in body:
        del body["_id"]
    parent = ip_o.getParentId()
    ins_result = mongoInstance.insertInDb(pentest, "ips", body, parent)
    iid = ins_result.inserted_id
    ip_o._id = iid
    if ip_o.in_scopes:
        ip_o.addAllChecks()
    return {"res":True, "iid":iid}

@permission("pentester")
def update(pentest, ip_iid, body):
    mongoInstance = MongoClient.getInstance()
    mongoInstance.updateInDb(pentest, "ips", {"_id":ObjectId(ip_iid)}, {"$set":body}, False, True)
    return True

