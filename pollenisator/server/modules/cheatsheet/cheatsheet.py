"""
CheckItem in cheatsheet module,
A checkitem is something you want to test in a pentest. It is then instanciated many time for each pentest as CheckInstances.
"""
from typing import Any, Dict, Iterator, List, Optional, Tuple, Union, cast
from typing_extensions import TypedDict
from bson import ObjectId
import pymongo
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.models.element import Element

CheckItemInsertResult = TypedDict('CheckItemInsertResult', {'res': bool, 'iid': ObjectId})

class CheckItem(Element):
    """Represents a checkitem object.

    Attributes:
        coll_name: collection name in pollenisator or pentest database
    """

    coll_name = 'checkitems'

    def __init__(self, pentest: str, valuesFromDb: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize a CheatSheet object. If valuesFromDb is provided, it is used to initialize the object. 
        Otherwise, the object is initialized with default values.

        Args:
            pentest (str): The name of the current pentest.
            valuesFromDb (Optional[Dict[str, Any]], optional): The values from the database. Defaults to None.
        """
        if valuesFromDb is None:
            valuesFromDb = {}
        super().__init__(pentest, valuesFromDb)
        self.initialize(valuesFromDb.get("title", ""),  valuesFromDb.get("pentest_types"),
                        valuesFromDb.get("lvl", ""), str(valuesFromDb.get("ports", "")),
                        int(valuesFromDb.get("priority", 0)), int(valuesFromDb.get("max_thread", 1)),
                        valuesFromDb.get("description", ""), str(valuesFromDb.get("category", "")),
                        valuesFromDb.get("check_type", ""), int(valuesFromDb.get("step", 0)), 
                        valuesFromDb.get("commands"), valuesFromDb.get("defect_tags"), valuesFromDb.get("script"), valuesFromDb.get("infos"))

    def initialize(self, title: str, pentest_types: Optional[List[str]] = None, lvl: str = "", ports: str = "", priority: int = 0, max_thread: int = 1, description: str = "", category: str = "", check_type: str = "manual", step: int = 1, commands: Optional[List[str]] = None, defect_tags: Optional[List[str]] = None, script: Optional[str] = None, infos: Optional[Dict[str, Any]] = None) -> 'CheckItem':
        """
        Initialize this CheatSheet object with the provided parameters.

        Args:
            title (str): The title of the CheatSheet.
            pentest_types (Optional[List[str]], optional): The types of pentests this CheatSheet applies to. Defaults to None.
            lvl (str, optional): The level of the CheatSheet. Defaults to "".
            ports (str, optional): The ports associated with the CheatSheet. Defaults to "".
            priority (int, optional): The priority of the CheatSheet. Defaults to 0.
            max_thread (int, optional): The maximum number of threads for the CheatSheet. Defaults to 1.
            description (str, optional): The description of the CheatSheet. Defaults to "".
            category (str, optional): The category of the CheatSheet. Defaults to "".
            check_type (str, optional): The type of check for the CheatSheet. Defaults to "manual".
            step (int, optional): The step of the CheatSheet. Defaults to 1.
            commands (Optional[List[str]], optional): The commands of the CheatSheet. Defaults to None.
            defect_tags (Optional[List[str]], optional): The defect tags of the CheatSheet. Defaults to None.
            script (Optional[str], optional): The script of the CheatSheet. Defaults to None.
            infos (Optional[Dict[str, Any]], optional): The additional information of the CheatSheet. Defaults to None.

        Returns:
            CheatSheet: The initialized CheatSheet object.
        """
        self.type = "checkitem"
        self.title = title
        self.ports = ports
        self.lvl = lvl
        self.description = description
        self.category = category
        self.check_type = check_type
        self.priority = priority
        self.max_thread = max_thread
        self.step = step
        self.commands = [] if commands is None else commands
        self.defect_tags = [] if defect_tags is None else defect_tags
        self.script = script
        self.pentest_types = [] if pentest_types is None else pentest_types
        self.infos = {} if infos is None else infos
        return self

    @classmethod
    def fetchObjects(cls, _pentest: str, pipeline: Dict[str, Any]) -> Iterator['CheckItem']:
        """
        Fetch many commands from database and return a Cursor to iterate over model objects.

        Args:
            pipeline (Dict[str, Any]): A Mongo search pipeline.

        Returns:
            Iterator[CheckItem]: A cursor to iterate on model objects.
        """
        dbclient = DBClient.getInstance()
        pipeline["type"] = "checkitem"
        ds = dbclient.findInDb("pollenisator", cls.coll_name, pipeline, True)
        if ds is None:
            return None
        for d in ds:
            yield CheckItem("pollenisator",d)

    @classmethod
    def fetchObject(cls, _pentest: str, pipeline: Dict[str, Any]) -> Optional['CheckItem']:
        """
        Fetch many commands from database and return a Cursor to iterate over model objects.

        Args:
            _pentest (str): The name of the current pentest.
            pipeline (Dict[str, Any]): A Mongo search pipeline.

        Returns:
            Optional[CheckItem]: A cursor to iterate on model objects, None if no object is found.
        """
        dbclient = DBClient.getInstance()
        pipeline["type"] = "checkitem"
        d = dbclient.findInDb("pollenisator", cls.coll_name, pipeline, False)
        if d is None:
            return None
        return CheckItem("pollenisator", d)

    def getData(self) -> Dict[str, Any]:
        """
        Get the data of this CheckItem object as a dictionary.
        
        Returns:
            Dict[str, Any]: The data of this CheckItem object.
        """
        return {"_id": self._id, "type":self.type, "title":self.title,"pentest_types":self.pentest_types, "lvl":self.lvl, "ports":self.ports,
                "priority":self.priority, "max_thread":self.max_thread, "description": self.description, "category":self.category,
                "check_type":self.check_type, "step":self.step, "parent":self.parent,
                "commands":self.commands,"defect_tags":self.defect_tags, "script":self.script, "infos":self.infos}

    def addInDb(self) -> CheckItemInsertResult:
        """
        Add the check item to the database

        Returns:
            CheckItemInsertResult: the result of the insert function
        """
        res: CheckItemInsertResult = CheckItem.doInsert(self.pentest, self.getData())
        return res

    def deleteFromDb(self) -> int:
        """
        Delete this checkitem from the database.

        Returns:
            int: 0 if the deletion was unsuccessful, otherwise the result of the deletion operation.
        """
        dbclient = DBClient.getInstance()
        pentests = dbclient.listPentestUuids()
        for pentest in pentests:
            dbclient.deleteFromDb(pentest, CheckItem.coll_name, {"check_iid":ObjectId(self.getId())}, many=True, notify=True)
        res = dbclient.deleteFromDb("pollenisator", CheckItem.coll_name, {"_id":ObjectId(self.getId())}, many=False, notify=True)
        if res is None:
            return 0
        return res

    @classmethod
    def doInsert(cls, pentest: str, data: Dict[str, Any]) -> CheckItemInsertResult:
        """
        Insert a checkitem into the database.

        Args:
            pentest (str): The pentest name.
            data (Dict[str, Any]): The data to insert.

        Returns:
            CheckItemInsertResult: A dictionary with the result of the insertion.
        """
        if "_id" in data:
            del data["_id"]
        if "type" in data:
            del data["type"]
        dbclient = DBClient.getInstance()
        data["type"] = "checkitem"
        existing = CheckItem.fetchObject("pollenisator", {"title":data["title"]})
        if existing is not None:
            return {"res":False, "iid":existing.getId()}
        ins_result = dbclient.insertInDb(
            pentest, CheckItem.coll_name, data, notify=True)
        ins_result = cast(pymongo.results.InsertOneResult, ins_result)
        iid = ins_result.inserted_id
        return {"res": True, "iid": iid}

    def apply_retroactively(self, pentest: str) -> None:
        """
        Apply the CheatSheet retroactively. This method checks if the CheatSheet can be applied to any existing elements.

        Args:
            pentest (str): The name of the current pentest.
        """
        class_registered = Element.getClassWithTrigger(self.lvl)
        if class_registered is None:
            return
        elif class_registered == Element:
            Element.apply_retroactively_custom(pentest, self)
            return
        all_objects = class_registered.fetchObjects(pentest, {})
        if all_objects is None:
            return
        for obj in all_objects:
            obj.checkAllTriggers()
