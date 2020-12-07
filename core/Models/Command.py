"""Command Model."""
from core.Models.Element import Element
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
                        possible keys with default values are : _id (None), parent (None), tags([]), infos({}), name(""), sleep_between("0"), priority("0),
                        max_thread("1"), text(""), lvl("network"), ports(""), safe(True), types([]), indb="pollenisator", timeout="300"
        """
        if valuesFromDb is None:
            valuesFromDb = dict()
        super().__init__(valuesFromDb.get("_id", None), valuesFromDb.get("parent", None),  valuesFromDb.get(
            "tags", []), valuesFromDb.get("infos", {}))
        self.initialize(valuesFromDb.get("name", ""), valuesFromDb.get("sleep_between", 0),
                        valuesFromDb.get("priority", 0), valuesFromDb.get(
                            "max_thread", 1),
                        valuesFromDb.get("text", ""), valuesFromDb.get(
                            "lvl", "network"),
                        valuesFromDb.get("ports", ""),
                        bool(valuesFromDb.get("safe", True)), valuesFromDb.get("types", []), valuesFromDb.get("indb", "pollenisator"), valuesFromDb.get("timeout", 300), valuesFromDb.get("infos", {}))

    def initialize(self, name, sleep_between=0, priority=0, max_thread=1, text="", lvl="network", ports="", safe=True, types=None, indb=False, timeout=300, infos=None):
        """Set values of command
        Args:
            name: the command name
            sleep_between: delay to wait between two call to this command. Default is 0
            priority: priority of the command (0 is highest). Default is 0
            max_thread: number of parallel execution possible of this command. Default is 1
            text: the command line options. Default is "".
            lvl: level of the command. Must be either "wave", "network", "domain", "ip", "port". Default is "network"
            ports: allowed proto/port, proto/service or port-range for this command
            safe: True or False with True as default. Indicates if autoscan is authorized to launch this command.
            types: type for the command. Lsit of string. Default to None.
            indb: db name : global (pollenisator database) or  local pentest database
            timeout: a timeout to kill stuck tools and retry them later. Default is 300 (in seconds)
            infos: a dictionnary with key values as additional information. Default to None
        Returns:
            this object
        """
        self.name = name
        self.sleep_between = sleep_between
        self.priority = priority
        self.max_thread = max_thread
        self.text = text
        self.lvl = lvl
        self.ports = ports
        self.safe = bool(safe)
        self.infos = infos if infos is not None else {}
        self.indb = indb
        self.timeout = timeout
        self.types = types if types is not None else []
        return self
            
    def __str__(self):
        """
        Get a string representation of a command.

        Returns:
            Returns the command's name string.
        """
        return self.name

    def getDbKey(self):
        """Return a dict from model to use as unique composed key.
        Returns:
            A dict (1 key :"name")
        """
        return {"name": self.name}
