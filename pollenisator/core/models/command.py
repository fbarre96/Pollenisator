"""Command Model."""
from typing import Any, Dict, Iterator, List, Optional

from bson import ObjectId
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.models.element import Element


class Command(Element):
    """Represents a command object to be run on designated scopes/ips/ports.

    Attributes:
        coll_name: collection name in pollenisator or pentest database
    """

    coll_name: str = "commands"

    def __init__(self, pentest: str, valuesFromDb: Optional[Dict[str, Any]] = None) -> None:
        """
        Constructor to initialize the command object.

        Args:
            pentest (str): An object representing a penetration test.
            valuesFromDb (Optional[Dict[str, Any]], optional): A dict holding values to load into the object. 
                A mongo fetched command is optimal. Possible keys with default values are : _id (None), parent (None), 
                infos({}), name(""), text(""), lvl("network"), ports(""), safe(True), types([]), indb("pollenisator"), 
                owners(""), timeout("300"). Defaults to None.
        """
        if valuesFromDb is None:
            valuesFromDb = {}
        super().__init__(pentest, valuesFromDb)
        if valuesFromDb:
            self.initialize(valuesFromDb.get("name", ""), valuesFromDb.get("bin_path", ""), valuesFromDb.get("plugin", ""),
                            valuesFromDb.get("text", ""), valuesFromDb.get("indb", "pollenisator"),
                            valuesFromDb.get("original_iid"), valuesFromDb.get("owners", []), valuesFromDb.get("timeout", 300), valuesFromDb.get("infos", {}))

    def initialize(self, name: str, bin_path: str, plugin: str = "Default", text: str = "", indb: str = "pollenisator", 
                   original_iid: Optional[str] = None, owners: Optional[List[str]] = None, timeout: int = 300, 
                   infos: Optional[Dict[str, Any]] = None) -> 'Command':
        """
        Set values of command.

        Args:
            name (str): The command name.
            bin_path (str): Local command, binary path or command line.
            plugin (str, optional): Plugin that goes with this command. Defaults to "Default".
            text (str, optional): The command line options. Defaults to "".
            indb (str, optional): DB name : global (pollenisator database) or local pentest database..
            original_iid (Optional[str], optional): Original iid as string. Defaults to None.
            owners (Optional[List[str]], optional): The user owning this command. Defaults to None.
            timeout (int, optional): A timeout to kill stuck tools and retry them later. Defaults to 300 (in seconds).
            infos (Optional[Dict[str, Any]], optional): A dictionary with key values as additional information. Defaults to None.

        Returns:
            Command: This object.
        """
        self.name = name
        self.bin_path = bin_path
        self.plugin = plugin
        self.text = text
        self.original_iid = original_iid
        self.infos = infos if infos is not None else {}
        self.indb: str = indb
        self.owners = owners if owners is not None else []
        self.timeout = timeout
        return self

    def getData(self) -> Dict[str, Any]:
        """
        Returns a dictionary containing the data of the command.

        Returns:
            Dict[str, Any]: A dictionary containing the data of the command.
        """
        return {"name": self.name, "bin_path":self.bin_path, "plugin":self.plugin,  "text": self.text,
                "timeout": self.timeout,
                "indb":self.indb, "_id": self.getId(),  "infos": self.infos}

    def deleteFromDb(self) -> int:
        """
        Delete the command from the database.

        Returns:
            int: 0 if the deletion was unsuccessful, otherwise the result of the deletion operation.
        """
        dbclient = DBClient.getInstance()
        #TODO : delete from checks
        pentests = set(self.pentest)
        # Remove from all waves this command.
        if self.indb == "pollenisator":
            pentest_uuids = dbclient.listPentestUuids()
            if pentest_uuids is not None:
                pentests.union(pentest_uuids)
        else:
            pentests.add(self.indb)

        for pentest in pentests:
            waves = dbclient.findInDb(pentest, "waves", {}, True)
            for wave in waves:
                toBeUpdated = wave["wave_commands"]
                if self.getId() in wave["wave_commands"]:
                    toBeUpdated.remove(self.getId())
                    dbclient.updateInDb(pentest, "waves", {"_id": wave["_id"]}, {
                        "$set": {"wave_commands": toBeUpdated}}, False)
            # Remove all tools refering to this command's name.
            dbclient.deleteFromDb(pentest,
                                    "tools", {"name": self.name}, True, True)
        res: int = dbclient.deleteFromDb(self.indb, "commands", {
            "_id": ObjectId(self.getId())}, False, True)
        if res is None:
            return 0
        else:
            return res

    @classmethod
    def getSearchableTextAttribute(cls) -> List[str]:
        """
        Returns a list of attribute names that can be used for searching.

        Returns:
            List[str]: A list containing the attribute names that can be used for searching. In this case, it's ["name"].
        """
        return ["name"]

    def __str__(self) -> str:
        """
        Get a string representation of a command.

        Returns:
            str: Returns the command's name string.
        """
        return self.name

    def getDbKey(self) -> Dict[str, str]:
        """
        Return a dict from model to use as unique composed key.

        Returns:
            Dict[str, str]: A dict with one key-value pair: {"name": self.name}.
        """
        return {"name": self.name}

    @classmethod
    def fetchObjects(cls, pentest: Any, pipeline: Dict[str, Any]) -> Iterator['Command']:
        """
        Fetch many commands from database and return a Cursor to iterate over Command objects.

        Args:
            pentest (Any): An object representing a penetration test.
            pipeline (Dict[str, Any]): A Mongo search pipeline.

        Returns:
            Optional[Iterator['Command']]: A cursor to iterate on Command objects, or None if no results are found.
        """
        dbclient = DBClient.getInstance()

        results = dbclient.findInDb(pentest, "commands", pipeline, True)
        if results is None:
            return []
        for result in results:
            yield Command(pentest, result)

    @classmethod
    def fetchObject(cls, pentest: Any, pipeline: Dict[str, Any]) -> Optional['Command']:
        """
        Fetch one command from database and return a Command object.

        Args:
            pentest (Any): An object representing a penetration test.
            pipeline (Dict[str, Any]): A Mongo search pipeline.

        Returns:
            Optional[Command]: A Command object, or None if no results are found.
        """
        dbclient = DBClient.getInstance()
        result = dbclient.findInDb(pentest, "commands", pipeline, False)
        if result is None:
            return None
        return Command(pentest, result)

    @classmethod
    def getList(cls, pipeline: Optional[Dict[str, Any]] = None, targetdb: str = "pollenisator") -> List[ObjectId]:
        """
        Get all command's name registered on database

        Args:
            pipeline (Optional[Dict[str, Any]], optional): Condition for mongo search. Defaults to None.
            targetdb (str, optional): The target database. Defaults to "pollenisator".

        Returns:
            List[str]: The list of commands name found inside the database. List may be empty.
        """
        if pipeline is None:
            pipeline = {}
        return [command.getId() for command in cls.fetchObjects(targetdb, pipeline)]
