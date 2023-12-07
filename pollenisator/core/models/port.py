"""Port Model"""

from pollenisator.core.models.element import Element
from pollenisator.core.models.tool import Tool
from pollenisator.core.models.defect import Defect
from bson.objectid import ObjectId


class Port(Element):
    """
    Represents an Port object that defines an Port that will be targeted by port level tools.

    Attributes:
        coll_name: collection name in pollenisator database
    """
    coll_name = "ports"

    def __init__(self, valuesFromDb=None):
        """Constructor
        Args:
            valueFromDb: a dict holding values to load into the object. A mongo fetched interval is optimal.
                        possible keys with default values are : _id (None), parent (None), infos({}),
                        ip(""), port(""), proto("tcp"), service(""), product(""), notes("")
        """
        if valuesFromDb is None:
            valuesFromDb = {}
        super().__init__(valuesFromDb.get("_id", None), valuesFromDb.get("parent", None), valuesFromDb.get("infos", {}))
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