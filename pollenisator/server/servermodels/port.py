import time
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
from pollenisator.core.components.logger_config import logger
from pymongo import UpdateOne
from pollenisator.server.modules.cheatsheet.cheatsheet import CheckItem
from pollenisator.server.modules.cheatsheet.checkinstance import CheckInstance, delete as checkinstance_delete
from pollenisator.server.permission import permission

class ServerPort(Port, ServerElement):
    command_variables = ["port","port.proto","port.service","port.product","port.infos.*"]
    def __init__(self, pentest="", *args, **kwargs):
        dbclient = DBClient.getInstance()
        if pentest != "":
            self.pentest = pentest
        elif dbclient.current_pentest != "":
            self.pentest = dbclient.current_pentest
        else:
            raise ValueError("An empty pentest name was given and the database is not set in mongo instance.")
        super().__init__(*args, **kwargs)


    def getParentId(self):
        dbclient = DBClient.getInstance()
        return dbclient.findInDb(self.pentest, "ips", {"ip": self.ip}, False)["_id"]
    
    def checkAllTriggers(self):
        self.add_port_checks()

    def add_port_checks(self):
        self.addChecks(["port:onServiceUpdate"])

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
    
    def update_service(self):
        return update(self.pentest, self._id, {"service": self.service})
    
    @staticmethod
    def get_allowed_ports(checkitem, ports):
        allowed_ports_services = checkitem.ports.split(",")
        ret = []
        cache = {}
        for port in ports:
            key = (port.port, port.proto, port.service)
            if key in cache:
                if cache[key]:
                    ret.append(port)
                continue
            res = checkCommandService(allowed_ports_services, port.port, port.proto, port.service)
            if res:
                ret.append(port)
            cache[key] = res
        return ret
    
    @classmethod
    def bulk_insert(cls, pentest, ports_to_add):
        if not ports_to_add:
            return
        dbclient = DBClient.getInstance()
        dbclient.create_index(pentest, "ports", [("port", 1), ("proto", 1), ("ip", 1)])
        update_operations = []
        computers = []
        dcs = []
        msql = []
        start = time.time()
        for port in ports_to_add:
            data = PortController(port).getData()
            if "service" in data:
                del data["service"]
            if "_id" in data:
                del data["_id"]
            if int(port.port) == 445:
                computers.append({"name":"", "ip":port.ip, "domain":"", "admins":[], "users":[], "infos":{"is_dc":False}})
            elif int(port.port) == 88:
                computers.append({"name":"", "ip":port.ip, "domain":"", "admins":[], "users":[], "infos":{"is_dc":True}})
            elif int(port.port) == 1433 or port.service == "ms-sql":
                computers.append({"name":"", "ip":port.ip, "domain":"", "admins":[], "users":[], "infos":{"is_sqlserver":True}})
            update_operations.append(UpdateOne({"port": port.port, "proto": port.proto, "ip": port.ip}, {"$setOnInsert": data, "$set":{"service":port.service}}, upsert=True))
        logger.info(f"Crating port update operations took {time.time() - start}")
        start = time.time()
        result = dbclient.bulk_write(pentest, "ports", update_operations)
        logger.info(f"Bluk writing ports took {time.time() - start}")
        upserted_ids = result.upserted_ids
        if not upserted_ids:
            return
        ports_inserted = ServerPort.fetchObjects(pentest, {"_id":{"$in":list(upserted_ids.values())}})
        start = time.time()
        Computer.bulk_insert(pentest, computers)
        
            
        logger.info(f"Computer update took {time.time() - start}")
        
        CheckInstance.bulk_insert_for(pentest, ports_inserted, "port", ["port:onServiceUpdate"], f_get_impacted_targets=cls.get_allowed_ports)
        # lkp = {}
        # port_keys = set()
        # or_conditions = []
        # for port in ports_to_add:
        #     hashable_key = tuple(port.getDbKey().values())
        #     lkp[hashable_key] = PortController(port).getData()
        #     del lkp[hashable_key]["_id"]
        #     port_keys.add(hashable_key)
        #     or_conditions.append({"port": port.port, "proto": port.proto, "ip": port.ip})
        # dbclient.create_index(pentest, "ports", [("port", 1), ("proto", 1), ("ip", 1)])
        # existing_ports = list(ServerPort.fetchObjects(pentest, {"$or": or_conditions}))
        # existing_ports_as_keys = [] if existing_ports is None else [existing_port.getHashableDbKey() for existing_port in existing_ports]
        # existing_ports_as_keys = set(existing_ports_as_keys)
        # to_add = port_keys - existing_ports_as_keys
        # things_to_insert = [lkp[port] for port in to_add]

         # Insert new
        # if things_to_insert:
        #     res = dbclient.insertInDb(pentest, "ports", things_to_insert, multi=True)
        #     ports_inserted = ServerPort.fetchObjects(pentest, {"_id":{"$in":res.inserted_ids}})
        #     CheckInstance.bulk_insert_for(pentest, ports_inserted, "port", ["port:onServiceUpdate"], check_func=cls.check_allowed)
        # return {"inserted":to_add, "failed":existing_ports}

@permission("pentester")
def delete(pentest, port_iid):
    dbclient = DBClient.getInstance()

    port_o = ServerPort(pentest, dbclient.findInDb(pentest, "ports", {"_id":ObjectId(port_iid)}, False))
    tools = dbclient.findInDb(pentest, "tools", {"port": port_o.port, "proto": port_o.proto,
                                             "ip": port_o.ip}, True)
    for tool in tools:
        tool_delete(pentest, tool["_id"])
    checks = dbclient.findInDb(pentest, "checkinstances",
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
        return res

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
    elif int(port_o.port) == 1433 or (port_o.service == "ms-sql"):
        res = computer_insert(pentest, {"name":"", "ip":port_o.ip, "domain":"", "admins":[], "users":[], "infos":{"is_sqlserver":True}})
        if not res["res"]:
            comp = Computer.fetchObject(pentest, {"_id":ObjectId(res["iid"])})
            comp.infos.is_sqlserver = True
            comp.update()
    port_o.add_port_checks()
    
    return {"res":True, "iid":iid}

@permission("pentester")
def update(pentest, port_iid, body):
    dbclient = DBClient.getInstance()
    
    oldPort = ServerPort(pentest, dbclient.findInDb(pentest, "ports", {"_id": ObjectId(port_iid)}, False))
    if oldPort is None:
        return
    dbclient.updateInDb(pentest, "ports", {"_id":ObjectId(port_iid)}, {"$set":body}, False, True)
    
    port_o = ServerPort(pentest, dbclient.findInDb(pentest, "ports", {"_id": ObjectId(port_iid)}, False))
    oldService = oldPort.service
    if oldService != port_o.service:
        
        dbclient.deleteFromDb(pentest, "tools", {
                                "lvl": "port:onServiceUpdate", "ip": oldPort.ip, "port": oldPort.port, "proto": oldPort.proto, "status":{"$ne":"done"}}, many=True)
        dbclient.deleteFromDb(pentest, "checkinstances", {
                                "lvl": "port:onServiceUpdate", "ip": oldPort.ip, "port": oldPort.port, "proto": oldPort.proto, "status":{"$ne":"done"}}, many=True)     
        port_o.add_port_checks()
    return True
   