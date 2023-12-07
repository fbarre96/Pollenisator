from bson import ObjectId
from pollenisator.core.components.mongo import DBClient
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


class ServerIp(Ip, ServerElement):
    command_variables = ["ip","ip.infos.*"]

    def __init__(self, pentest="", *args, **kwargs):
        dbclient = DBClient.getInstance()
        if pentest != "":
            self.pentest = pentest
        elif dbclient.current_pentest != "":
            self.pentest = dbclient.current_pentest
        else:
            raise ValueError("An empty pentest name was given and the database is not set in mongo instance.")
        super().__init__(*args, **kwargs)


    def initialize(self, ip="", notes="", in_scopes=None, infos=None):
        """Set values of ip
        Args:
            ip: the host (ip or domain) to represent
            notes: notes concerning this IP (opt). Default to ""
            in_scopes: a list of scopes that matches this host. If empty this IP will be OOS (Out of Scope). Default to None
            infos: a dictionnary of additional info
        Returns:
            this object
        """
        self.ip = ip
        self.notes = notes
        self.in_scopes = in_scopes if in_scopes is not None else self.getScopesFittingMe()
        self.infos = infos if infos is not None else {}
        return self
    
    def getScopesFittingMe(self):
        """Returns a list of scope objects ids where this IP object fits.
        Returns:
            a list of scopes objects Mongo Ids where this IP/Domain is in scope.
        """
        ret = []
        dbclient = DBClient.getInstance()
        scopes = dbclient.findInDb(self.pentest, "scopes", {})
        if scopes is None:
            return ret
        for scope in scopes:
            if self.fitInScope(scope["scope"]):
                ret.append(str(scope["_id"]))
        return ret


    @classmethod
    def getIpsInScope(cls, pentest, scopeId):
        """Returns a list of IP objects that have the given scope id in there matching scopes.
        Args:
            scopeId: a mongo ObjectId of a scope object.
        Returns:
            a mongo cursor of IP objects matching the given scopeId
        """
        dbclient = DBClient.getInstance()
        ips = dbclient.findInDb(pentest, "ips", {"in_scopes": {"$elemMatch": {"$eq": str(scopeId)}}})
        for ip in ips:
            yield ServerIp(pentest, ip)

    @classmethod
    def replaceCommandVariables(cls, pentest, command, data):
        command = command.replace("|ip|", data.get("ip", ""))
        dbclient = DBClient.getInstance()
        ip_db = dbclient.findInDb(pentest, "ips", {"ip":data.get("ip", "")}, False)
        if ip_db is None:
            return command
        ip_infos = ip_db.get("infos", {})
        for info in ip_infos:
            command = command.replace("|ip.infos."+str(info)+"|", command)
        return command

    @classmethod
    def completeDetailedString(cls, data):
        return data.get("ip", "")+" "
    
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
            dbclient = DBClient.getInstance()
            ip_in_db = dbclient.findInDb(self.pentest, "ips", {"ip": ip_real}, False)
            if ip_in_db is None:
                return None
            self.parent = ip_in_db["_id"]
            update(self.pentest, self._id, {"parent": self.parent})
            return ip_in_db["_id"]
        return None
    
    def checkAllTriggers(self):
        self.add_ip_checks()

    def add_ip_checks(self):
        if self.in_scopes:
            self.addChecks(["ip:onAdd"])

    def addChecks(self, lvls):
        """
        Add the appropriate checks (level check and wave's commands check) for this scope.
        """
        dbclient = DBClient.getInstance()
        search = {"lvl":{"$in": lvls}}
        pentest_type = dbclient.findInDb(self.pentest, "settings", {"key":"pentest_type"}, False)
        if pentest_type is not None:
            search["pentest_types"] = pentest_type["value"]
        # query mongo db commands collection for all commands having lvl == network or domain 
        checkitems = CheckItem.fetchObjects(search)
        if checkitems is None:
            return
        for check in checkitems:
            CheckInstance.createFromCheckItem(self.pentest, check, str(self._id), "ip")
    
    @classmethod
    def getTriggers(cls):
        """
        Return the list of trigger declared here
        """
        return ["ip:onAdd"]

    def addInDb(self):
        return insert(self.pentest, IpController(self).getData())
    
    @classmethod
    def bulk_insert(cls, pentest, ips_to_add, look_scopes=True):
        if not ips_to_add:
            return
        dbclient = DBClient.getInstance()
        scopes = []
        settings = {}
        if look_scopes:
            scopes = list(dbclient.findInDb(pentest, "scopes", {}, True))
            if scopes is None:
                scopes = []
            settings_scope_ip = dbclient.findInDb(pentest, "settings", {"key":"include_domains_with_ip_in_scope"}, False)
            if isinstance(settings_scope_ip.get("value", None), str):
                settings_scope_ip = settings_scope_ip.get("value", "").lower() == "true"
            else:
                settings_scope_ip = settings_scope_ip.get("value", False)
            settings_all_domains = dbclient.findInDb(pentest,"settings", {"key":"include_all_domains"}, False)
            if isinstance(settings_all_domains.get("value", None), str):
                settings_all_domains = settings_all_domains.get("value", "").lower() == "true"
            else:
                settings_all_domains = settings_all_domains.get("value", False)
            settings_top_domain = dbclient.findInDb(pentest, "settings", {"key":"include_domains_with_topdomain_in_scope"}, False)
            if isinstance(settings_top_domain.get("value", None), str):
                settings_top_domain = settings_top_domain.get("value", "").lower() == "true"
            else:
                settings_top_domain = settings_top_domain.get("value", False)
            settings["include_domains_with_ip_in_scope"] = settings_scope_ip
            settings["include_all_domains"] = settings_all_domains
            settings["include_domains_with_topdomain_in_scope"] = settings_top_domain
        lkp = {}
        ip_keys = set()
        for ip in ips_to_add:
            if look_scopes:
                fitted_scope = []
                for scope in scopes:
                    if ip.fitInScope(scope["scope"], settings):
                        fitted_scope.append(str(scope["_id"]))
                ip.in_scopes = fitted_scope
            lkp[ip.ip] = IpController(ip).getData()
            del lkp[ip.ip]["_id"]
            ip_keys.add(ip.ip)
        dbclient.create_index(pentest, "ips", [("ip",1)])
        existing_ips = dbclient.findInDb(pentest, "ips", {"ip":{"$in":list(ip_keys)}}, multi=True)
        existing_ips_as_key = [] if existing_ips is None else [x.get("ip") for x in existing_ips]
        existing_ips_as_key = set(existing_ips_as_key)
        to_add = ip_keys - existing_ips_as_key
        things_to_insert = [lkp[ip] for ip in to_add]
        # Insert new
        res = None
        if things_to_insert:
            res = dbclient.insertInDb(pentest, "ips", things_to_insert, multi=True)
        if res is None:
            return
        ips_inserted = ServerIp.fetchObjects(pentest, {"_id":{"$in":res.inserted_ids}, "in_scopes":{"$exists": True, "$ne": []}})
        CheckInstance.bulk_insert_for(pentest, ips_inserted, "ip", ["ip:onAdd"])
        return ips_inserted
                    
    # WIP : add all checks, fix notif sent but not received ?

    def update(self):
        return update(self.pentest, self._id, IpController(self).getData())

@permission("pentester")
def delete(pentest, ip_iid):
    dbclient = DBClient.getInstance()
    ip_dic = dbclient.findInDb(pentest, "ips", {"_id":ObjectId(ip_iid)}, False)
    if ip_dic is None:
        return 0
    tools = dbclient.findInDb(pentest, "tools",
                                {"ip": ip_dic["ip"]}, True)
    for tool in tools:
        tool_delete(pentest, tool["_id"])
    checks = dbclient.findInDb(pentest, "checkinstances",
                                {"target_iid": str(ip_iid)}, True)
    for check in checks:
        checkinstance_delete(pentest, check["_id"])
    defects = dbclient.findInDb(pentest, "defects",
                                    {"ip": ip_dic["ip"], "$or": [{"port": {"$exists": False}}, {"port": None}]}, True)
    for defect in defects:
        defect_delete(pentest, defect["_id"])
    ports = dbclient.findInDb(pentest, "ports",
                                {"ip": ip_dic["ip"]}, True)
    for port in ports:
        port_delete(pentest, port["_id"])
    res = dbclient.deleteFromDb(pentest, "ips", {"_id": ObjectId(ip_iid)}, False)
    if res is None:
        return 0
    else:
        return res

@permission("pentester")
def insert(pentest, body):
    dbclient = DBClient.getInstance()
    ip_o = ServerIp(pentest, body)
    base = ip_o.getDbKey()
    existing = dbclient.findInDb(pentest, 
            "ips", base, False)
    if existing is not None:
        return {"res":False, "iid":existing["_id"]}
    if "_id" in body:
        del body["_id"]
    parent = ip_o.getParentId()
    ins_result = dbclient.insertInDb(pentest, "ips", body, parent)
    iid = ins_result.inserted_id
    ip_o._id = iid
    ip_o.add_ip_checks()
    return {"res":True, "iid":iid}

@permission("pentester")
def update(pentest, ip_iid, body):
    dbclient = DBClient.getInstance()
    old = ServerIp.fetchObject(pentest, {"_id":ObjectId(ip_iid)})
    dbclient.updateInDb(pentest, "ips", {"_id":ObjectId(ip_iid)}, {"$set":body}, False, True)
    new = ServerIp.fetchObject(pentest, {"_id":ObjectId(ip_iid)})
    new.add_ip_checks()
    return True

