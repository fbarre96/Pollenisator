"""Ip Model. Describes Hosts (not just IP now but domains too)"""

from core.Models.Element import Element
from bson.objectid import ObjectId
from netaddr import IPNetwork, IPAddress
from netaddr.core import AddrFormatError
from core.Models.Port import Port
from core.Models.Tool import Tool
from core.Models.Defect import Defect
from core.Components.Utils import isNetworkIp, performLookUp
import re


class Ip(Element):
    """
    Represents an Ip object that defines an Ip or a domain that will be targeted by ip tools.

    Attributes:
        coll_name: collection name in pollenisator database
    """
    coll_name = "ips"

    def __init__(self, valuesFromDb=None):
        """Constructor
        Args:
            valueFromDb: a dict holding values to load into the object. A mongo fetched interval is optimal.
                        possible keys with default values are : _id (None), parent (None), tags([]), infos({}),
                        ip(""), notes(""), in_scopes(None)
        """
        if valuesFromDb is None:
            valuesFromDb = {}
        super().__init__(valuesFromDb.get("_id", None), valuesFromDb.get("parent", None), valuesFromDb.get(
            "tags", []), valuesFromDb.get("infos", {}))
        self.initialize(valuesFromDb.get("ip", ""), valuesFromDb.get("notes", ""),
                        valuesFromDb.get("in_scopes", None), tags=valuesFromDb.get("tags", []), infos=valuesFromDb.get("infos", {}))

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

    def fitInScope(self, scope):
        """Checks if this IP is the given scope.
        Args:
            scope: a string of perimeter (Network Ip, IP or domain)
        Returns:
            boolean: True if this ip/domain is in given scope. False otherwise.
        """
        if isNetworkIp(scope):
            if Ip.checkIpScope(scope, self.ip):
                return True
        elif Ip.isSubDomain(scope, self.ip):
            return True
        elif self.ip == scope:
            return True
        return False

    def addPort(self, values):
        """
        Add a port object to database associated with this Ip.

        Args:
            values: A dictionary crafted by PortView containg all form fields values needed.

        Returns:ret
                '_id': The mongo ObjectId _idret of the inserted port document or None if insertion failed (unicity broken).
        """
        portToInsert = {"ip": self.ip, "port": str(
            values["Port"]), "proto": str(values["Protocole"]), "service": values["Service"], "product": values["Product"]}
        newPort = Port()
        newPort.initialize(
            self.ip, portToInsert["port"], portToInsert["proto"], portToInsert["service"], portToInsert["product"])
        return newPort.addInDb()

    @classmethod
    def checkIpScope(cls, scope, ip):
        """
        Check if the given ip is in the given scope

        Args:
            scope: A network range ip or a domain
            ip: An ipv4 like X.X.X.X

        Returns:
                True if the ip is in the network range or if scope == ip. False otherwise.
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


    

    def __str__(self):
        """
        Get a string representation of an ip.

        Returns:
            Returns the string ipv4 of this ip.
        """
        return self.ip

    def getDbKey(self):
        """Return a dict from model to use as unique composed key.
        Returns:
            A dict (1 key :"ip")
        """
        return {"ip": self.ip}

    @classmethod
    def isSubDomain(cls, parentDomain, subDomainTest):
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
    def isIp(cls, ip):
        """Checks if the given string is a valid IP
        Args:
            ip: a string that could be representing an ip
        Returns:
            boolean
        """
        return re.search(r"([0-9]{1,3}\.){3}[0-9]{1,3}", ip) is not None

