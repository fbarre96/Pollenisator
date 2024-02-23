"""Port Model"""

import time
from typing import Dict, Iterable, List, Tuple, Union, cast

from pymongo import UpdateOne, InsertOne
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.components.utils import checkCommandService
from pollenisator.core.models.defect import Defect
from pollenisator.core.models.element import Element
from bson.objectid import ObjectId
from pollenisator.core.models.tool import Tool
from pollenisator.server.modules.activedirectory.computers import Computer
from pollenisator.server.modules.cheatsheet.cheatsheet import CheckItem
from pollenisator.server.modules.cheatsheet.checkinstance import CheckInstance
from pollenisator.server.servermodels.port import PortInsertResult, insert as port_insert, update as port_update
from pollenisator.core.components.logger_config import logger


class Port(Element):
    """
    Represents an Port object that defines an Port that will be targeted by port level tools.

    Attributes:
        coll_name: collection name in pollenisator database
    """
    command_variables = ["port","port.proto","port.service","port.product","port.infos.*"]
    coll_name = "ports"

    def __init__(self, pentest, valuesFromDb=None):
        """Constructor
        Args:
            valueFromDb: a dict holding values to load into the object. A mongo fetched interval is optimal.
                        possible keys with default values are : _id (None), parent (None), infos({}),
                        ip(""), port(""), proto("tcp"), service(""), product(""), notes("")
        """
        if valuesFromDb is None:
            valuesFromDb = {}
        super().__init__(pentest, valuesFromDb)
        self.initialize(valuesFromDb.get("ip", ""), valuesFromDb.get("port", ""),
                        valuesFromDb.get("proto", "tcp"), valuesFromDb.get(
                            "service", ""), valuesFromDb.get("product", ""),
                        valuesFromDb.get("notes", ""),  valuesFromDb.get("infos", {}))

    def initialize(self, ip, port="", proto="tcp", service="", product="", notes="", infos=None):
        """Set values of port
        Args:
            ip: the parent host (ip or domain) where this port is open
            port: a port number as string. Default ""
            proto: a protocol to reach this port ("tcp" by default, send "udp" if udp port.) Default "tcp"
            service: the service running behind this port. Can be "unknown". Default ""
            notes: notes took by a pentester regarding this port. Default ""
            infos: a dictionnary of additional info. Default is None (empty dict)
        Returns:
            this object
        """
        self.ip = ip
        self.port = port
        self.proto = proto
        self.service = service
        self.product = product
        self.notes = notes
        self.infos = infos if infos is not None else {}
        return self

    def getData(self):
        """Return port attributes as a dictionnary matching Mongo stored ports
        Returns:
            dict with keys ip, port, proto, service, product, notes, _id,  infos
        """
        return {"ip": self.ip, "port": self.port, "proto": self.proto,
                "service": self.service, "product": self.product, "notes": self.notes, "_id": self.getId(), "infos": self.infos}

    def __str__(self):
        """
        Get a string representation of a port.

        Returns:
            Returns the string protocole/port number.
        """
        return self.proto+"/"+str(self.port)
    
    @classmethod
    def getSearchableTextAttribute(cls):
        return ["port", "proto", "service", "product"]

    def getDetailedString(self):
        """Returns a detailed string describing this port.
        Returns:
            string : ip:proto/port
        """
        return str(self.ip)+":"+str(self)


    def getDbKey(self):
        """Return a dict from model to use as unique composed key.
        Returns:
            A dict (3 keys :"ip", "port", "proto")
        """
        return {"ip": self.ip, "port": self.port, "proto": self.proto}

    def getHashableDbKey(self):
        """Return a hashable tuple from model to use as unique composed key.
        Returns:
            A tuple (3 keys :"ip", "port", "proto")
        """
        return tuple(self.getDbKey().values())

    def getParentId(self):
        dbclient = DBClient.getInstance()
        return dbclient.findInDb(self.pentest, "ips", {"ip": self.ip}, False)["_id"]

    def checkAllTriggers(self) -> None:
        """Check all triggers for this port object"""
        self.add_port_checks()

    def add_port_checks(self) -> None:
        """Check service related triggers for this port object"""
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
        checkitems = CheckItem.fetchObjects("pollenisator", search)
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

    def addInDb(self) -> PortInsertResult:
        """
        Add this port to the database.
        Returns:
            PortInsertResult: A dictionary containing the result of the operation and the id of the inserted port.
        """
        res: PortInsertResult = port_insert(self.pentest, self.getData())
        return res

    def update(self) -> bool:
        """
        Update port in the database with the current object's data.
        
        Returns:
            bool: True if the update was successful, False otherwise.
        """
        res: bool = port_update(self.pentest, ObjectId(self._id), self.getData())
        return res

    def deleteFromDb(self) -> int:
        """
        Delete this port from the database.

        Returns:
            int: The number of deleted ports.
        """
        dbclient = DBClient.getInstance()
        tools = Tool.fetchObjects(self.pentest, {"port": self.port, "proto": self.proto, "ip": self.ip})
        if tools is not None:
            for tool in tools:
                tool = cast(Tool, tool)
                tool.deleteFromDb()
        checks = CheckInstance.fetchObjects(self.pentest, {"target_iid": str(self._id)})
        if checks is not None:
            for check in checks:
                check.deleteFromDb()
        defects = Defect.fetchObjects(self.pentest, {"port": self.port, "proto": self.proto, "ip": self.ip})
        if defects is not None:
            for defect in defects:
                defect = cast(Defect, defect)
                defect.deleteFromDb()
        res = dbclient.deleteFromDb(self.pentest, "ports", {"_id": ObjectId(self.getId())}, False)
        if res is None:
            return 0
        else:
            return res

    def update_service(self) -> bool:
        """
        Update the port service only in the database with the current object's data.
        Returns:
            bool: True if the update was successful, False otherwise.
        """
        res: bool = port_update(self.pentest, self._id, {"service": self.service})
        return res

    @staticmethod
    def get_allowed_ports(checkitem: 'CheckItem', ports: List['Port']) -> List['Port']:
        """
        Returns the list of allowed ports based on the checkitem.

        Args:
            checkitem (CheckItem): The checkitem object containing the allowed ports and services.
            ports (List[Port]): The list of ports to be checked.

        Returns:
            List[Port]: The list of allowed ports.
        """
        allowed_ports_services = checkitem.ports.split(",")
        ret: List['Port'] = []
        cache: Dict[Tuple[str, str, str], bool] = {}
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
    def bulk_insert(cls, pentest: str, ports_to_add: List['Port']) -> None:
        """
        Inserts multiple ports into the database in a single operation.

        Args:
            pentest (str): The name of the pentest.
            ports_to_add (List[Port]): A list of Port objects to be inserted into the database.
        """
        if not ports_to_add:
            return
        dbclient = DBClient.getInstance()
        dbclient.create_index(pentest, "ports", [("port", 1), ("proto", 1), ("ip", 1)])
        update_operations: List[UpdateOne] = []
        computers = []
        start = time.time()
        for port in ports_to_add:
            data = port.getData()
            if "service" in data:
                del data["service"]
            if "_id" in data:
                del data["_id"]
            if int(port.port) == 88:
                computers.append({"name":"", "ip":port.ip, "domain":"", "admins":[], "users":[], "infos.is_dc":True})
            elif int(port.port) == 445:
                computers.append({"name":"", "ip":port.ip, "domain":"", "admins":[], "users":[]})
            elif int(port.port) == 1433 or port.service == "ms-sql":
                computers.append({"name":"", "ip":port.ip, "domain":"", "admins":[], "users":[], "infos.is_sqlserver":True})
            update_operations.append(UpdateOne({"port": port.port, "proto": port.proto, "ip": port.ip}, {"$setOnInsert": data, "$set":{"service":port.service}}, upsert=True))
        logger.info("Crating port update operations took %s", str(time.time() - start))
        start = time.time()
        result = dbclient.bulk_write(pentest, "ports", cast(List[Union[InsertOne, UpdateOne]], update_operations))
        logger.info("Bluk writing ports took %s", time.time() - start)
        upserted_ids = result.upserted_ids
        if not upserted_ids and result.modified_count == 0:
            return
        start = time.time()
        Computer.bulk_insert(pentest, computers)
        logger.info("Computer update took %s", str(time.time() - start))
        if not upserted_ids:
            return
        ports_inserted = Port.fetchObjects(pentest, {"_id":{"$in":list(upserted_ids.values())}})
        CheckInstance.bulk_insert_for(pentest, cast(Iterable, ports_inserted), "port", ["port:onServiceUpdate"], f_get_impacted_targets=cls.get_allowed_ports)
