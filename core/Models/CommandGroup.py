"""Command Group Model."""
from core.Models.Element import Element
from bson.objectid import ObjectId


class CommandGroup(Element):
    """Represents a command group object that defines settings and ressources shared by many Commands.

    Attributes:
        coll_name: collection name in pollenisator database
    """
    coll_name = "group_commands"

    def __init__(self, valuesFromDb=None):
        """Constructor
        Args:
            valueFromDb: a dict holding values to load into the object. A mongo fetched command group is optimal.
                        possible keys with default values are : _id (None), parent (None), tags([]), infos({}),
                        name(""), sleep_between("0"), commands([]),
                        max_thread("1")
        """
        if valuesFromDb is None:
            valuesFromDb = {}
        super().__init__(valuesFromDb.get("_id", None), valuesFromDb.get("parent", None), valuesFromDb.get(
            "tags", []), valuesFromDb.get("infos", {}))
        self.initialize(valuesFromDb.get("name", ""), valuesFromDb.get("sleep_between", 0), valuesFromDb.get("commands", []),
                        valuesFromDb.get("max_thread", 1), valuesFromDb.get("infos", {}))

    def initialize(self, name, sleep_between=0, commands=None, max_thread=1, infos=None):
        """Set values of command group
        Args:
            name: the command group name
            sleep_between: delay to wait between two call to this command. Default is 0.
            commands: list of command names that are part of this group. Default is None and stores an empty array
            max_thread: number of parallel execution possible of this command. Default is 1.
            infos: a dictionnary with key values as additional information. Default to None
        Returns:
            this object
        """
        if commands is None:
            commands = []
        self.name = name
        self.sleep_between = int(sleep_between)
        self.commands = commands
        self.max_thread = int(max_thread)
        self.infos = infos if infos is not None else {}
        return self

    def __str__(self):
        """
        Get a string representation of a command group.

        Returns:
            Returns the string "Command Group".
        """
        return self.name

    def getDbKey(self):
        """Return a dict from model to use as unique composed key.
        Returns:
            A dict (1 key: "_id")
        """
        return {"_id": self._id}
