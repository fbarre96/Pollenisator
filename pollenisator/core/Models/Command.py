"""Command Model."""
from pollenisator.core.Models.Element import Element
from bson.objectid import ObjectId


class Command(Element):
    """Represents a command object to be run on designated scopes/ips/ports.

    Attributes:
        coll_name: collection name in pollenisator or pentest database
    """

    coll_name = "commands"

    def __init__(self, valuesFromDb=None):
        """Constructor
        Args:
            valueFromDb: a dict holding values to load into the object. A mongo fetched command is optimal.
                        possible keys with default values are : _id (None), parent (None), tags([]), infos({}), name(""), 
                         text(""), lvl("network"), ports(""), safe(True), types([]), indb="pollenisator", owner="",timeout="300"
        """
        if valuesFromDb is None:
            valuesFromDb = dict()
        super().__init__(valuesFromDb.get("_id", None), valuesFromDb.get("parent", None),  valuesFromDb.get(
            "tags", []), valuesFromDb.get("infos", {}))
        self.initialize(valuesFromDb.get("name", ""), valuesFromDb.get("bin_path", ""), valuesFromDb.get("plugin", ""), 
                        valuesFromDb.get("text", ""), valuesFromDb.get(
                            "lvl", "network"),
                        valuesFromDb.get("ports", ""),
                        bool(valuesFromDb.get("safe", True)), valuesFromDb.get("types", []), valuesFromDb.get("indb", "pollenisator"), valuesFromDb.get("owner", ""), valuesFromDb.get("timeout", 300), valuesFromDb.get("infos", {}))

    def initialize(self, name, bin_path, plugin="Default", text="", lvl="network", ports="", safe=True, types=None, indb=False, owner="", timeout=300, infos=None):
        """Set values of command
        Args:
            name: the command name
            bin_path: local command, binary path or command line
            plugin: plugin that goes with this command
            text: the command line options. Default is "".
            lvl: level of the command. Must be either "wave", "network", "domain", "ip", "port". Default is "network"
            ports: allowed proto/port, proto/service or port-range for this command
            safe: True or False with True as default. Indicates if autoscan is authorized to launch this command.
            types: type for the command. Lsit of string. Default to None.
            indb: db name : global (pollenisator database) or  local pentest database
            owner: the user owning this command
            timeout: a timeout to kill stuck tools and retry them later. Default is 300 (in seconds)
            infos: a dictionnary with key values as additional information. Default to None
        Returns:
            this object
        """
        self.name = name
        self.bin_path = bin_path
        self.plugin = plugin
        self.text = text
        self.lvl = lvl
        self.ports = ports
        self.safe = bool(safe)
        self.infos = infos if infos is not None else {}
        self.indb = indb
        self.owner = owner
        self.timeout = timeout
        self.types = types if types is not None else []
        return self
            
    def __str__(self):
        """
        Get a string representation of a command.

        Returns:
            Returns the command's name string.
        """
        return self.owner+":"+self.name

    def getDbKey(self):
        """Return a dict from model to use as unique composed key.
        Returns:
            A dict (1 key :"name")
        """
        return {"name": self.name, "owner":self.owner}
