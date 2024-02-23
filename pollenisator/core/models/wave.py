"""Wave Model. Stores which command should be launched and associates Interval and Scope"""

from typing import Any, Dict, Iterator, List, Optional, cast
from typing_extensions import TypedDict

from bson import ObjectId
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.models.tool import Tool
from pollenisator.core.models.element import Element
from pollenisator.core.models.interval import Interval
import pollenisator.core.components.utils as utils
from pollenisator.server.modules.cheatsheet.cheatsheet import CheckItem
from pollenisator.server.modules.cheatsheet.checkinstance import CheckInstance

WaveInsertResult = TypedDict('WaveInsertResult', {'res': bool, 'iid': ObjectId})

class Wave(Element):
    """
    Represents a Wave object. A wave is a series of tools to execute.

    Attributes:
        coll_name: collection name in pollenisator database
        command_variables: list of variables that can be used in commands
    """
    coll_name = "waves"
    command_variables = ["wave"]

    def __init__(self, pentest: str, valuesFromDb: Optional[Dict[str, Any]] = None) -> None:
        """
        Constructor for the Wave class.

        Args:
            pentest (str): The name of the pentest.
            valuesFromDb (Optional[Dict[str, Any]], optional): A dictionary holding values to load into the object.
                A mongo fetched wave is optimal. Possible keys with default values are : _id(None), parent(None),
                infos({}), wave(""), wave_commands([]). Defaults to None.
        """
        if valuesFromDb is None:
            valuesFromDb = {}
        super().__init__(pentest, valuesFromDb)
        self.initialize(valuesFromDb.get("wave", ""),
                        valuesFromDb.get("wave_commands", []), valuesFromDb.get("infos", {}))

    def initialize(self, wave: str = "", wave_commands: Optional[List[ObjectId]] = None, infos: Optional[Dict[str, Any]] = None) -> 'Wave':
        """
        Set values of scope.

        Args:
            wave (str, optional): The wave name. Defaults to "".
            wave_commands (Optional[List[ObjectId]], optional): A list of command names that are to be launched in this wave. Defaults to None (empty list).
            infos (Optional[Dict[str, Any]], optional): A dictionary of additional info. Defaults to None (empty dict).

        Returns:
            Wave: This object.
        """
        self.wave = wave
        self.wave_commands = wave_commands if wave_commands is not None else []
        self.infos = infos if infos is not None else {}
        return self

    def getData(self) -> Dict[str, Any]:
        """
        Return wave attributes as a dictionary matching Mongo stored waves.

        Returns:
            Dict[str, Any]: A dictionary with keys wave, wave_commands, _id, and infos.
        """
        return {"wave": self.wave, "wave_commands": self.wave_commands, "_id": self.getId(), "infos": self.infos}


    def __str__(self) -> str:
        """
        Get a string representation of a wave.

        Returns:
            str: Returns the wave id (name).
        """
        return self.wave

    @classmethod
    def getSearchableTextAttribute(cls) -> List[str]:
        """
        Return the attribute of the model that should be used for search.
        
        Returns:
            List[str]: The list of searchable attribute names.
        """
        return ["wave"]

    def getAllTools(self) -> Optional[Iterator[Element]]:
        """
        Return all tools being part of this wave as a list of mongo fetched tools dict.
        Differs from getTools as it fetches all tools of the name and not only tools of level wave.

        Returns:
            Optional[Iterator[Element]]: List of raw mongo data dictionaries for each tool.
        """
        res: Optional[Iterator[Element]] = Tool.fetchObjects(self.pentest, {"wave": self.wave})
        return res


    def getDbKey(self) -> Dict[str, Any]:
        """
        Return a dict from model to use as unique composed key.

        Returns:
            Dict[str, Any]: A dictionary with a single key "wave".
        """
        return {"wave": self.wave}

    def isLaunchableNow(self) -> bool:
        """
        Returns True if the tool matches criteria to be launched 
        (current time matches one of interval object assigned to this wave)

        Returns:
            bool: True if the tool can be launched now, False otherwise.
        """
        intervals: Optional[Iterator[Element]] = Interval.fetchObjects(self.pentest, {"wave": self.wave})
        if intervals is None:
            return False
        for intervalModel in intervals:
            interval_model: Interval = cast(Interval, intervalModel)
            if utils.fitNowTime(interval_model.dated, interval_model.datef):
                return True
        return False

    @classmethod
    def replaceCommandVariables(cls, _pentest: str, command: str, data: Dict[str, Any]) -> str:
        """
        Replace the variable "|wave|" in the command with the wave name from the data dictionary.

        Args:
            _pentest (str): The name of the pentest.
            command (str): The command string where variables will be replaced.
            data (Dict[str, Any]): The data dictionary containing the wave name.

        Returns:
            str: The command string with the "|wave|" variable replaced by the wave name.
        """
        return command.replace("|wave|", data.get("wave", ""))

    def checkAllTriggers(self) -> None:
        """
        Check all check items triggers on this wave
        """
        self.add_wave_checks()

    def add_wave_checks(self) -> None:
        """
        Check all wave type checks items triggers on this wave
        """
        self.addChecks(["wave:onAdd"])

    def addChecks(self, lvls: List[str]) -> None:
        """
        Add the appropriate checks (level check and wave's commands check) for this scope.

        Args:
            lvls (List[str]): List of triggers to checks
        """
        dbclient = DBClient.getInstance()
        search = {"lvl":{"$in": lvls}}
        pentest_type = dbclient.findInDb(self.pentest, "settings", {"key":"pentest_type"}, False)
        if pentest_type is not None:
            search["pentest_types"] = pentest_type["value"]
        checkitems = CheckItem.fetchObjects("pollenisator", search)
        if checkitems is None:
            return None
        for check in checkitems:
            CheckInstance.createFromCheckItem(self.pentest, check, ObjectId(self._id), "wave")

    def getTools(self) -> Optional[Iterator[Element]]:
        """
        Return scope assigned tools as a list of mongo fetched tools dict.

        Returns:
            Optional[Iterator[Element]]: List of raw mongo data dictionaries for each tool.
        """
        return Tool.fetchObjects(self.pentest, {"wave": self.wave, "lvl": {"$in": self.getTriggers()}})

    def removeAllTool(self, command_name: str) -> None:
        """
        Remove from every member of this wave the old tool corresponding to given command name but only if the tool is not done.

        Args:
            command_name (str): The command that we want to remove all the tools.
        """
        tools = Tool.fetchObjects(self.pentest, {"name": command_name, "wave": self.wave})
        if tools is None:
            return
        for tool in tools:
            tool = cast(Tool, tool)
            if "done" not in tool.getStatus():
                tool.delete()

    def deleteFromDb(self) -> int:
        """
        Delete the wave from the database. All tools and intervals associated with the wave are also deleted from the database.

        Returns:
            int: The result of the deletion operation. If the wave was not found, None is returned. Otherwise, the number of deleted documents is returned.
        """
        dbclient = DBClient.getInstance()
        dbclient.deleteFromDb(self.pentest, "tools", {"wave": self.wave}, True)
        dbclient.deleteFromDb(self.pentest, "intervals", {"wave": self.wave}, True)
        checks = CheckInstance.fetchObjects(self.pentest, {"target_iid": self.getId()})
        if checks is not None:
            for check in checks:
                check.deleteFromDb()
        res = dbclient.deleteFromDb(self.pentest, "waves", {"_id": ObjectId(self.getId())}, False)
        if res is None:
            return 0
        else:
            return res

    def addInDb(self) -> WaveInsertResult:
        """
        Insert a new wave into the database.

        Returns:
            WaveInsertResult: A dictionary containing the result of the operation and the id of the wave.
        """
        # Checking unicity
        dbclient = DBClient.getInstance()
        existing = Wave.fetchObject(self.pentest, {"wave": self.wave})
        if existing is not None:
            return {"res":False, "iid":existing.getId()}
        # Inserting scope
        res_insert = dbclient.insertInDb(self.pentest, "waves", {"wave": self.wave, "wave_commands": list(self.wave_commands)})
        ret = res_insert.inserted_id
        self._id = ret
        self.add_wave_checks()
        return {"res":True, "iid":ret}

    @classmethod
    def getTriggers(cls) -> List[str]:
        """
        Return the list of trigger declared here

        Returns:
            List[str]: List of triggers
        """
        return ["wave:onAdd"]
