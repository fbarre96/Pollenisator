"""Ip Model. Describes Hosts (not just IP now but domains too)"""

from typing import Any, Dict, Iterator, List, Optional, cast
from typing_extensions import TypedDict
from bson import ObjectId
import re
from netaddr import IPNetwork, IPAddress
from netaddr.core import AddrFormatError
from pollenisator.core.models.defect import Defect
from pollenisator.core.models.element import Element
from pollenisator.core.models.port import Port
from pollenisator.server.modules.cheatsheet.cheatsheet import CheckItem
from pollenisator.server.modules.cheatsheet.checkinstance import CheckInstance
from pollenisator.core.components.utils import isNetworkIp, performLookUp
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.models.tool import Tool

IpInsertResult = TypedDict('IpInsertResult', {'res': bool, 'iid': ObjectId})
PortInsertResult = TypedDict('PortInsertResult', {'res': bool, 'iid': ObjectId})


class Ip(Element):
    """
    Represents an Ip object that defines an Ip or a domain that will be targeted by ip tools.

    Attributes:
        coll_name: collection name in pollenisator database
        command_variables: list of variables that can be used in commands
    """
    coll_name = "ips"
    command_variables: List[str] = ["ip","ip.infos.*"]

    def __init__(self, pentest: str, valuesFromDb: Optional[Dict[str, Any]] = None) -> None:
        """
        Constructor for the IP class.

        Args:
            pentest (str): The name of the pentest.
            valuesFromDb (Optional[Dict[str, Any]], optional): A dictionary holding values to load into the object. 
            A mongo fetched interval is optimal. Possible keys with default values are : _id (None), parent (None),  
            infos({}), ip(""), notes(""), in_scopes(None). Defaults to None.
        """
        if valuesFromDb is None:
            valuesFromDb = {}
        self.parent = None
        super().__init__(pentest, valuesFromDb)
        if valuesFromDb:
            self.initialize(valuesFromDb.get("ip", ""), valuesFromDb.get("notes", ""),
                        valuesFromDb.get("in_scopes", None),  infos=valuesFromDb.get("infos", {}))

    def initialize(self, ip: str = "", notes: str = "", in_scopes: Optional[List[ObjectId]] = None, infos: Optional[Dict[str, Any]] = None) -> 'Ip':
        """
        Set values of IP.

        Args:
            ip (str, optional): The host (IP or domain) to represent. Defaults to "".
            notes (str, optional): Notes concerning this IP. Defaults to "".
            in_scopes (Optional[List[ObjectId]], optional): A list of scopes that matches this host. 
            If empty this IP will be OOS (Out of Scope). Defaults to None.
            infos (Optional[Dict[str, Any]], optional): A dictionary of additional info. Defaults to None.

        Returns:
            IP: This object.
        """
        self.ip = ip
        self.notes = notes
        self.in_scopes: List[ObjectId] = in_scopes if in_scopes is not None else self.getScopesFittingMe()
        self.infos = infos if infos is not None else {}
        self.repr_string = self.getDetailedString()
        return self

    def getData(self) -> Dict[str, Any]:
        """
        Returns IP attributes as a dictionary matching Mongo stored IPs.

        Returns:
            Dict[str, Any]: A dictionary with keys "ip", "in_scopes", "notes", "_id", and "infos".
        """
        return {"ip": self.ip, "in_scopes": self.in_scopes, "notes": self.notes, "_id": self.getId(), "infos": self.infos}

    def fitInScope(self, scope: str, settings: Optional[Dict[str, Any]] = None) -> bool:
        """
        Checks if this IP is in the given scope.

        Args:
            scope (str): A string of perimeter (Network Ip, IP or domain).
            settings (Optional[Dict[str, Any]], optional): A dictionary of settings. 
            If not provided, settings will be fetched from the database. Defaults to None.

        Returns:
            bool: True if this ip/domain is in the given scope, False otherwise.
        """
        dbclient = DBClient.getInstance()
        if settings is None:
            settings_scope_ip = dbclient.findInDb(self.pentest, "settings", {"key":"include_domains_with_ip_in_scope"}, False)
            if isinstance(settings_scope_ip.get("value", None), str):
                settings_scope_ip = settings_scope_ip.get("value", "").lower() == "true"
            settings_all_domains = dbclient.findInDb(self.pentest,"settings", {"key":"include_all_domains"}, False)
            if isinstance(settings_all_domains.get("value", None), str):
                settings_all_domains = settings_all_domains.get("value", "").lower() == "true"
            settings_top_domain = dbclient.findInDb(self.pentest, "settings", {"key":"include_domains_with_topdomain_in_scope"}, False)
            if isinstance(settings_top_domain.get("value", None), str):
                settings_top_domain = settings_top_domain.get("value", "").lower() == "true"
        else:
            settings_scope_ip = settings.get("include_domains_with_ip_in_scope", False)
            settings_all_domains = settings.get("include_all_domains", False)
            settings_top_domain = settings.get("include_domains_with_topdomain_in_scope", False)
        if isNetworkIp(scope):
            if Ip.checkIpScope(scope, self.ip):
                return True
        elif settings_all_domains:
            return True
        elif Ip.isSubDomain(scope, self.ip) and settings_top_domain:
            return True
        elif self.ip == scope:
            return True
        elif settings_scope_ip:
            ip = performLookUp(self.ip)
            if ip is not None and Ip.checkIpScope(scope, ip):
                return True
        return False

    def addPort(self, values: Dict[str, Any]) -> PortInsertResult:
        """
        Add a port object to database associated with this Ip.

        Args:
            values (Dict[str, Any]): A dictionary crafted by PortView containing all form fields values needed.

        Returns:
            PortInsertResult: The mongo ObjectId _id of the inserted port document or None if insertion failed (unicity broken).
        """
        portToInsert = {"ip": self.ip, "port": str(
            values["Port"]), "proto": str(values["Protocole"]), "service": values["Service"], "product": values["Product"]}
        newPort = Port(self.pentest)
        newPort.initialize(
            self.ip, portToInsert["port"], portToInsert["proto"], portToInsert["service"], portToInsert["product"])
        return newPort.addInDb()

    @classmethod
    def checkIpScope(cls, scope: str, ip: str) -> bool:
        """
        Check if the given ip is in the given scope

        Args:
            scope (str): A network range ip or a domain
            ip (str): An ipv4 like X.X.X.X

        Returns:
            bool: True if the ip is in the network range or if scope == ip. False otherwise.
        """
        if cls.isIp(scope):
            network_mask = scope.split("/")
            mask = "32"
            if len(network_mask) == 2:
                mask = network_mask[1]
            try:
                res = IPAddress(ip) in IPNetwork(network_mask[0]+"/"+mask)
            except AddrFormatError:
                return False
            except ValueError:
                return False
            return res
        elif scope == ip:
            return True
        return False

    def __str__(self) -> str:
        """
        Get a string representation of an ip.

        Returns:
            (str) Returns the string ipv4 of this ip.
        """
        return self.ip

    @classmethod
    def getSearchableTextAttribute(cls) -> List[str]:
        """
        Returns a list of attribute names that can be used for searching.

        Returns:
            A list containing the attribute names that can be used for searching. In this case, it's ["ip"].
        """
        return ["ip"]

    def getDbKey(self) -> Dict[str, Any]:
        """Return a dict from model to use as unique composed key.

        Returns:
            Dict[str, Any]: A dict (1 key :"ip")
        """
        return {"ip": self.ip}

    @classmethod
    def isSubDomain(cls, parentDomain: str, subDomainTest: str) -> bool:
        """Check if the given domain is a subdomain of another given domain
        Args:
            parentDomain: a domain that could be the parent domain of the second arg
            subDomainTest: a domain to be tested as a subdomain of first arg
        Returns:
            bool
        """
        splitted_domain = subDomainTest.split(".")
        # Assuring to check only if there is a domain before the tld (.com, .fr ... )
        topDomainExists = len(splitted_domain) > 2
        if topDomainExists:
            if ".".join(splitted_domain[1:]) == parentDomain:
                return True
        return False

    @classmethod
    def isIp(cls, ip: str) -> bool:
        """Checks if the given string is a valid IP
        Args:
            ip: a string that could be representing an ip
        Returns:
            bool
        """
        return re.search(r"([0-9]{1,3}\.){3}[0-9]{1,3}", ip) is not None


    def getScopesFittingMe(self) -> List[ObjectId]:
        """Returns a list of scope objects ids where this IP object fits.

        Returns:
            List[ObjectId]: a list of scopes objects Mongo Ids where this IP/Domain is in scope.
        """
        ret = []
        dbclient = DBClient.getInstance()
        scopes = dbclient.findInDb(self.pentest, "scopes", {})
        if scopes is None:
            return ret
        for scope in scopes:
            if self.fitInScope(scope["scope"]):
                ret.append(ObjectId(scope["_id"]))
        return ret


    @classmethod
    def getIpsInScope(cls, pentest: str, scopeId: ObjectId) -> Iterator['Ip']:
        """Returns a list of IP objects that have the given scope id in there matching scopes.
        Args:
            scopeId (ObjectId): a mongo ObjectId of a scope object.
        Returns:
            Iterator['Ip']: a mongo cursor of IP objects matching the given scopeId
        """
        dbclient = DBClient.getInstance()
        ips = dbclient.findInDb(pentest, "ips", {"in_scopes": {"$elemMatch": {"$eq": ObjectId(scopeId)}}})
        for ip in ips:
            yield Ip(pentest, ip)

    @classmethod
    def replaceCommandVariables(cls, pentest: str, command: str, data: Dict[str, Any]) -> str:
        """
        Replace command variables with actual values.

        Args:
            pentest (str): The name of the pentest.
            command (str): The command to replace variables in.
            data (Dict[str, Any]): The data containing the actual values.

        Returns:
            str: The command with variables replaced with actual values.
        """
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
    def completeDetailedString(cls, data: Dict[str, Any]) -> str:
        """
        Complete the detailed string with the IP address.

        Args:
            data (Dict[str, Any]): The data containing the IP address.

        Returns:
            str: The detailed string with the IP address appended.
        """
        return str(data.get("ip", ""))+" "

    def removeScopeFitting(self, pentest: str, scopeId: ObjectId) -> None:
        """
        Remove the given scopeId from the list of scopes this IP fits in.

        Args:
            pentest (str): The name of the pentest.
            scopeId (ObjectId): A mongo ObjectId of a scope object.
        """
        if ObjectId(scopeId) in self.in_scopes:
            self.in_scopes.remove(ObjectId(scopeId))
            self.updateInDb()
            if not self.in_scopes:
                tools = Tool.fetchObjects(pentest, {"ip": self.ip})
                if tools is None:
                    return
                for tool in tools:
                    tool = cast(Tool, tool)
                    tool.setOutOfScope(pentest)

    def addScopeFitting(self, pentest: str, scopeId: ObjectId) -> None:
        """
        Add the given scopeId to the list of scopes this IP fits in.

        Args:
            pentest (str): The name of the pentest.
            scopeId (ObjectId): A mongo ObjectId of a Scope object.
        """
        if not self.in_scopes:
            tools = Tool.fetchObjects(pentest, {"ip": self.ip})
            if tools is not None:
                for tool in tools:
                    tool = cast(Tool, tool)
                    tool.setInScope()
        if ObjectId(scopeId) not in self.in_scopes:
            self.in_scopes.append(ObjectId(scopeId))
            self.updateInDb()


    def getParentId(self) -> Optional[ObjectId]:
        """
        Get the parent id of the current IP. If the IP is private or an error occurs during lookup, return None. 
        If the IP is found in the database, set its id as the parent and return it.

        Returns:
            Optional[ObjectId]: The ObjectId of the parent IP if it exists, None otherwise.
        """
        if self.parent is not None:
            return self.parent
        try:
            if IPAddress(self.ip).is_private(): #pylint: disable=no-member
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
            self.parent = ObjectId(ip_in_db["_id"])
            self.updateInDb({"parent": self.parent})
            return self.parent
        return None

    def checkAllTriggers(self) -> None:
        """Check all triggers for this IP object."""
        self.add_ip_checks()

    def add_ip_checks(self) -> None:
        """Check all ip type checks items triggers on this IP."""
        if self.in_scopes:
            self.addChecks(["ip:onAdd"])

    def addChecks(self, lvls: List[str]) -> None:
        """
        Add the appropriate checks (level check and wave's commands check) for this scope.

        Args:
            lvls (List[str]): The levels to add checks for.
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
            CheckInstance.createFromCheckItem(self.pentest, check, ObjectId(self._id), "ip")

    @classmethod
    def getTriggers(cls) -> List[str]:
        """
        Return the list of trigger declared here

        Returns:
            List[str]: list of triggers
        """
        return ["ip:onAdd"]

    def updateInDb(self, data: Optional[Dict[str, Any]] = None) -> bool:
        """
        Update the current IP object in the database.

        Args:
            data (Optional[Dict[str, Any]): The new data to set in the database.

        Returns:
            bool: True if the operation was successful, False otherwise.
        """
        dbclient = DBClient.getInstance()
        new_data = self.getData()
        data = {} if data is None else data
        new_data |= data
        if "_id" in new_data:
            del new_data["_id"]
        dbclient.updateInDb(self.pentest, "ips", {"_id":ObjectId(self.getId())}, {"$set":new_data}, False, True)
        new_self = Ip(self.pentest, new_data)
        new_self.add_ip_checks()
        return True

    def addInDb(self) -> IpInsertResult:
        """
        Add the current IP object to the database.

        Returns:
            IpInsertResult: A dictionary with the result of the insertion.
        """
        dbclient = DBClient.getInstance()
        base = self.getDbKey()
        existing = Ip.fetchObject(self.pentest, base)
        if existing is not None:
            return {"res":False, "iid":existing.getId()}
        data = self.getData()
        if "_id" in data:
            del data["_id"]
        parent = self.getParentId()
        ins_result = dbclient.insertInDb(self.pentest, "ips", data, parent)
        iid = ins_result.inserted_id
        self._id = iid
        self.add_ip_checks()
        return {"res":True, "iid":iid}

    def deleteFromDb(self) -> int:
        """
        Delete the current IP object from the database.

        Returns:
            int: 0 if the deletion was unsuccessful, otherwise the result of the deletion operation.
        """
        dbclient = DBClient.getInstance()
        tools = Tool.fetchObjects(self.pentest, {"ip": self.ip})
        if tools is not None:
            for tool in tools:
                tool = cast(Tool, tool)
                tool.deleteFromDb()
        checks = CheckInstance.fetchObjects(self.pentest, {"target_iid": self.getId()})
        for check in checks:
            check.deleteFromDb()
        defects = Defect.fetchObjects(self.pentest, {"ip": self.ip,  "$or": [{"port": {"$exists": False}}, {"port": None}]})
        if defects is not None:
            for defect in defects:
                defect = cast(Defect, defect)
                defect.deleteFromDb()
        ports = Port.fetchObjects(self.pentest, {"ip": self.ip})
        if ports is not None:
            for port in ports:
                port = cast(Port, port)
                port.deleteFromDb()
        res = dbclient.deleteFromDb(self.pentest, "ips", {"_id": ObjectId(self.getId())}, False)
        if res is None:
            return 0
        else:
            return res


    @classmethod
    def bulk_insert(cls, pentest: str, ips_to_add: List['Ip'], look_scopes: bool = True) -> List['Ip']:
        """
        Bulk insert IP objects into the database.

        Args:
            pentest (str): The name of the pentest.
            ips_to_add (List['Ip']): A list of IP objects to add.
            look_scopes (bool, optional): Whether to look for scopes. Defaults to True.

        Returns:
            Optional[List[Ip]]: A list of the inserted IP objects if any were inserted, None otherwise.
        """
        if not ips_to_add:
            return []
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
                        fitted_scope.append(ObjectId(scope["_id"]))
                ip.in_scopes = fitted_scope
            lkp[ip.ip] = ip.getData()
            del lkp[ip.ip]["_id"]
            ip_keys.add(ip.ip)
        dbclient.create_index(pentest, "ips", [("ip",1)])
        existing_ips = dbclient.findInDb(pentest, "ips", {"ip":{"$in":list(ip_keys)}}, multi=True)
        existing_ips_as_key = set() if existing_ips is None else set([x.get("ip") for x in existing_ips])
        to_add = ip_keys - existing_ips_as_key
        things_to_insert = [lkp[ip] for ip in to_add]
        # Insert new
        res = None
        if things_to_insert:
            res = dbclient.insertManyInDb(pentest, "ips", things_to_insert)
        if res is None:
            return []
        ips_inserted = Ip.fetchObjects(pentest, {"_id":{"$in":res.inserted_ids}, "in_scopes":{"$exists": True, "$ne": []}})
        if ips_inserted is None:
            return []
        list_ips_inserted = list(ips_inserted)
        CheckInstance.bulk_insert_for(pentest, list_ips_inserted, "ip", ["ip:onAdd"])
        return cast(List[Ip], list_ips_inserted)


