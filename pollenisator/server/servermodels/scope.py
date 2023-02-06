from bson import ObjectId
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.models.scope import Scope
from pollenisator.server.modules.cheatsheet.checkinstance import CheckInstance, delete as checkinstance_delete
from pollenisator.server.modules.cheatsheet.cheatsheet import CheckItem
from pollenisator.server.servermodels.ip import ServerIp
from pollenisator.server.servermodels.element import ServerElement
from pollenisator.core.controllers.scopecontroller import ScopeController
from pollenisator.core.components.utils import JSONEncoder, isNetworkIp, performLookUp, isIp
import json
from pollenisator.server.permission import permission

class ServerScope(Scope, ServerElement):
    
    def __init__(self, pentest="", *args, **kwargs):
        dbclient = DBClient.getInstance()
        super().__init__(*args, **kwargs)
        if pentest != "":
            self.pentest = pentest
        elif dbclient.pentestName != "":
            self.pentest = dbclient.pentestName
        else:
            raise ValueError("An empty pentest name was given and the database is not set in mongo instance.")

    @classmethod
    def fetchObjects(cls, pentest, pipeline):
        dbclient = DBClient.getInstance()
        results = dbclient.findInDb(pentest, "scopes", pipeline)
        for result in results:
            yield(cls(pentest, result))

    @classmethod
    def replaceCommandVariables(cls, pentest, command, data):
        scope = data.get("scope", "")
        command = command.replace("|scope|", scope)
        if not isNetworkIp(scope):
            depths = scope.split(".")
            if len(depths) > 2:
                topdomain = ".".join(depths[1:])
            else:
                topdomain = ".".join(depths)
            command = command.replace("|parent_domain|", topdomain)
        return command
        
    @classmethod
    def completeDetailedString(cls, data):
        return data.get("scope", "")+" "

    def getParentId(self):
        dbclient = DBClient.getInstance()
        res = dbclient.findInDb(self.pentest, "waves", {"wave": self.wave}, False)
        return res["_id"]

    def addInDb(self):
        return insert(self.pentest, ScopeController(self).getData())

    @classmethod
    def getTriggers(cls):
        """
        Return the list of trigger declared here
        """
        return ["scope:onRangeAdd", "scope:onDomainAdd", "scope:onAdd"]

    def addChecks(self, lvls):
        """
        Add the appropriate checks (level check and wave's commands check) for this scope.
        """
        checkitems = CheckItem.fetchObjects({"lvl": {"$in": lvls}}) 
        if checkitems is None:
            return
        for check in checkitems:
            CheckInstance.createFromCheckItem(self.pentest, check, str(self._id), "scope")

    def getIpsFitting(self):
        """Returns a list of ip mongo dict fitting this scope
        Returns:
            A list ip IP dictionnary from mongo db
        """
        dbclient = DBClient.getInstance()
        ips = dbclient.findInDb(self.pentest, "ips", )
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
    dbclient = DBClient.getInstance()
    # deleting checks with scope 
    scope_o = ServerScope(pentest, dbclient.findInDb(pentest, "scopes", {"_id": ObjectId(scope_iid)}, False))
    checks = dbclient.findInDb(pentest, "cheatsheet", {"target_iid": str(scope_iid), "target_type": "scope"})
    for check in checks:
        checkinstance_delete(pentest, check["_id"])
    # Deleting this scope against every ips
    ips = ServerIp.getIpsInScope(pentest, scope_iid)
    for ip in ips:
        ip.removeScopeFitting(pentest, scope_iid)
    res = dbclient.deleteFromDb(pentest, "scopes", {"_id": ObjectId(scope_iid)}, False)
    
    parent_wave = dbclient.findInDb(pentest, "waves", {"wave": scope_o.wave}, False)
    if parent_wave is None:
        return
    dbclient.send_notify(pentest,
                            "waves", parent_wave["_id"], "update", "")
    # Finally delete the selected element
    if res is None:
        return 0
    else:
        return res.deleted_count
        
@permission("pentester")
def insert(pentest, body):
    dbclient = DBClient.getInstance()
    scope_o = ServerScope(pentest, body)
    # Checking unicity
    base = scope_o.getDbKey()
    existing = dbclient.findInDb(pentest, "scopes", base, False)
    if existing is not None:
        return {"res":False, "iid":existing["_id"]}
    if "_id" in body:
        del body["_id"]
    # Inserting scope
    parent = scope_o.getParentId()
    res_insert = dbclient.insertInDb(pentest, "scopes", base, parent)
    ret = res_insert.inserted_id
    scope_o._id = ret
    # adding the appropriate checks for this scope.
    
    if isNetworkIp(scope_o.scope):
        scope_o.addChecks(["scope:onRangeAdd", "scope:onAdd"])
    else:
        scope_o.addChecks(["scope:onDomainAdd", "scope:onAdd"])
        
    # Testing this scope against every ips
    ips = dbclient.findInDb(pentest, "ips", {})
    for ip in ips:
        ip_o = ServerIp(pentest, ip)
        if scope_o._id not in ip_o.in_scopes:
            if ip_o.fitInScope(scope_o.scope):
                ip_o.addScopeFitting(pentest, scope_o.getId())
    return {"res":True, "iid":ret}

@permission("pentester")
def update(pentest, scope_iid, body):
    dbclient = DBClient.getInstance()
    dbclient.updateInDb(pentest, "scopes", {"_id":ObjectId(scope_iid)}, {"$set":body}, False, True)
    return True