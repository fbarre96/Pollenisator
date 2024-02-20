"""Element parent Model. Common ground for every model"""
from bson.objectid import ObjectId
from datetime import datetime
from typing import Any, Dict, Iterator, List, Optional, Union, cast
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.components.tag import Tag

REGISTRY: Dict[str, 'Element'] = {}

def register_class(target_class):
    """Register the given class
    Args:
        target_class: type <class>
    """
    REGISTRY[target_class.__name__] = target_class


class MetaElement(type):
    """Metaclass for Element. 
    This metaclass is used to register all classes that inherit from Element"""
    def __new__(mcs, name, bases, class_dict):
        cls = type.__new__(mcs, name, bases, class_dict)
        if name not in REGISTRY:
            register_class(cls)
        return cls

class Element(metaclass=MetaElement):
    """
    Parent element for all model. This class should only be inherited.

    Attributes:
        coll_name:  collection name in pollenisator database
        command_variables: a list of command variables that can be used in commands
    """
    coll_name: str = ""
    command_variables: List[str] = []

    def __init__(self, pentest: str, valuesFromDb: Optional[Dict[str, Any]] = None) -> None:
        """
        Constructor to be inherited. Child model will all use this constructor.

        Args:
            pentest (str): The name of the pentest.
            valuesFromDb (Optional[Dict[str, Any]]): A dictionary of values from the database. Defaults to None.

        Raises:
            ValueError: If an empty pentest name was given and the database is not set in mongo instance.
        """
        # Initiate a cachedIcon for a model, not a class.
        dbclient = DBClient.getInstance()
        if pentest != "":
            self.pentest = pentest
        elif dbclient.current_pentest is None:
            raise ValueError("An empty pentest name was given and the database is not set in mongo instance.")
        elif dbclient.current_pentest != "":
            self.pentest = dbclient.current_pentest
        else:
            raise ValueError("An empty pentest name was given and the database is not set in mongo instance.")
        if valuesFromDb is not None:
            self.infos = valuesFromDb.get("infos", {})
            self._id: Union[None, ObjectId] = ObjectId(valuesFromDb.get("_id", None)) if valuesFromDb.get("_id", None) is not None else None
            self.parent: Union[None, ObjectId] = ObjectId(valuesFromDb.get("parent", None)) if valuesFromDb.get("parent", None) is not None else None
        self.cachedIcon = None
        self.repr_string = self.getDetailedString()

    def getData(self):
        """
        Returns a dictionary of the data stored in this object.
        
        Returns:
            Dict[str, Any]: A dictionary of the data stored in this object.
        """
        return {"_id":self._id, "infos":self.infos, "parent":self.parent}
    
    @classmethod
    def classFactory(cls, name: str) -> Optional['Element']:
        """
        Factory method to create a class instance based on the given name.

        Args:
            name (str): The name of the class to be created.

        Returns:
            Optional[Element]: The class that corresponds to the given name.
        """
        for class_name, class_type in REGISTRY.items():
            if name.endswith("s"):
                name = name[:-1]
            if class_name.lower() == name.lower():
                return class_type
        return None

    @classmethod
    def getSearchableTextAttribute(cls) -> List[str]:
        """
        Returns a list of attribute names that can be used for searching.

        Returns:
            List[str]: An empty list as this base class does not have any searchable text attributes.
        """
        return []

    @classmethod
    def replaceAllCommandVariables(cls, pentest: str, command: str, data: Dict[str, Any]) -> str:
        """
        Replace all command variables in the given command with their corresponding values.

        Args:
            pentest (str): The name of the pentest.
            command (str): The command in which to replace variables.
            data (Dict[str, Any]): A dictionary of variable names and their corresponding values.

        Returns:
            str: The command with all variables replaced by their corresponding values.
        """
        for _, class_type in REGISTRY.items():
            command = class_type.replaceCommandVariables(pentest, command, data)
        return command

    @classmethod
    def buildTextSearchQuery(cls, query: str) -> Dict[str, List[Dict[str, Dict[str, str]]]]:
        """
        Builds a MongoDB text search query for the given query string.

        Args:
            query (str): The text to search for.

        Returns:
            Dict[str, List[Dict[str, Dict[str, str]]]]: A MongoDB query that can be used to perform a text search.
        """
        list_of_pipes = []
        attrs = cls.getSearchableTextAttribute() + ["notes"]
        for attr in attrs:
            list_of_pipes.append({ attr:{"$regex": query, "$options": "i"}})
        return {"$or": list_of_pipes}

    @classmethod
    def replaceCommandVariables(cls, _pentest: str, command: str, _data: Dict[str, Any]) -> str:
        """
        Replace command variables in the given command with their corresponding values.

        Args:
            pentest (str): The name of the pentest.
            command (str): The command in which to replace variables.
            data (Dict[str, Any]): A dictionary of variable names and their corresponding values.

        Returns:
            str: The command with all variables replaced by their corresponding values.
        """
        return command

    @classmethod
    def getClassWithTrigger(cls, trigger: str) -> Optional['Element']:
        """
        Returns the class associated with the given trigger.

        Args:
            trigger (str): The trigger to search for.

        Returns:
           Optional['Element']: The class associated with the given trigger, or None if no such class exists.
        """
        for _, class_type in REGISTRY.items():
            trigger_test = trigger
            if len(trigger.split(":")) == 3:
                trigger_test = ":".join(trigger.split(":")[:2])
            triggers = class_type.getTriggers()
            triggers_test = [":".join(trigger.split(":")[:2]) for trigger in triggers]
            if trigger_test in triggers_test:
                return class_type
        return None

    @classmethod
    def completeDetailedString(cls, _data: Any) -> str:
        """
        Returns a detailed string representation of the given data.

        Args:
            _data (Any): The data to be represented as a string.

        Returns:
            str: An empty string as this base class does not provide a detailed string representation.
        """
        return ""

    def getDetailedString(self) -> str:
        """
        Returns a detailed string representation of the given data.

        Args:
            _data (Any): The data to be represented as a string.

        Returns:
            str: An empty string as this base class does not provide a detailed string representation.
        """
        return str(self)

    @classmethod
    def fetchObjects(cls, pentest: str, pipeline: Dict[str, Any]) -> Optional[Iterator['Element']]:
        """
        Fetch many commands from database and return a Cursor to iterate over model objects.

        Args:
            pentest (str): The name of the pentest.
            pipeline (Dict[str, Any]): A MongoDB search pipeline.

        Returns:
            Iterator: A cursor to iterate on model objects.
        """
        dbclient = DBClient.getInstance()
        ds = dbclient.findInDb(pentest, cls.coll_name, pipeline, True)
        if ds is None:
            return None
        for d in ds:
            yield cls(pentest, d)

    @classmethod
    def fetchObject(cls, pentest: str, pipeline: Dict[str, Any]) -> Optional['Element']:
        """
        Fetch a single command from the database and return a model object.

        Args:
            pentest (str): The name of the pentest.
            pipeline (Dict[str, Any]): A MongoDB search pipeline.

        Returns:
            Optional[Element]: A model object if found, None otherwise.
        """
        dbclient = DBClient.getInstance()
        d = dbclient.findInDb(pentest, cls.coll_name, pipeline, False)
        if d is None:
            return None
        return cls(pentest, d)

    def getTags(self) -> List[Tag]:
        """
        Fetches and returns the tags associated with this element.

        Returns:
            List[Tag]: A list of Tag objects associated with this element. If no tags are found, an empty list is returned.
        """
        if self is None:
            return []
        dbclient = DBClient.getInstance()
        tags = dbclient.findInDb(self.pentest, "tags", {"item_id": ObjectId(self.getId())}, False)
        if tags is None:
            return []
        return [Tag(tag) for tag in tags["tags"]]

    def checkAllTriggers(self) -> None:
        """
        Checks all triggers associated with this element and performs the necessary actions.
        """
        return

    def addTag(self, newTag: Union[str, Tag], override: bool = True) -> None:
        """
        Adds a new tag to this element. If the tag is already present, it is replaced if override is True.

        Args:
            newTag (Union[str, Tag]): The new tag to be added. Can be a string or a Tag object.
            override (bool, optional): Whether to replace the tag if it already exists. Defaults to True.
        """
        tags = self.getTags()
        newTag = Tag(newTag)
        if newTag.name not in [tag.name for tag in tags]:
            dbclient = DBClient.getInstance()
            for group in dbclient.getTagsGroups():
                if newTag in group:
                    i = 0
                    len_tags = len(tags)
                    while i < len_tags:
                        if tags[i] in group:
                            if override:
                                tags.remove(tags[i])
                                i -= 1
                            else:
                                continue
                        len_tags = len(tags)
                        i += 1
            tags.append(newTag)
            self.setTags(tags)
            dbclient.doRegisterTag(self.pentest, newTag)

    def delTag(self, tag: str) -> None:
        """Delete the given tag name in model if it has it
        Args:
            tag (str): a string describing a tag name.
        """
        dbclient = DBClient.getInstance()
        dbclient.updateInDb(self.pentest, "tags", {"item_id": ObjectId(self.getId())}, {"$pull":{"tags.name":tag}})

    def setTags(self, tags: List[Tag]) -> bool:
        """
        Set the model tags to given tags. This function also handles the addition and removal of tags, 
        and updates the database accordingly.

        Args:
            tags (List[Tag]): A list of tags.

        Returns:
            bool: Always returns True indicating the tags were successfully set.
        """
        dbclient = DBClient.getInstance()
        old_tags_res = self.getTags()
        old_tags = set()
        for old_tag in old_tags_res:
            old_tags.add(old_tag.name)
        new_tags = set()
        lk_new_tags = {}
        for tag in tags:
            dbclient.doRegisterTag(self.pentest, tag)
            new_tags.add(tag.name)
            lk_new_tags[tag.name] = tag
        deleted_tags = old_tags - new_tags
        added_tags = new_tags - old_tags
        target_type = self.__class__.name if hasattr(self.__class__, "name") else self.__class__.coll_name
        data_target = {"target_iid":ObjectId(self.getId()), "target_type":target_type, "tags":tags, "target_data":self.getData()}
        data_target["target_id"] = ObjectId(self.getId()) # FOR DEFECT ITS TARGET_ID, FOR CHECKS ITS TARGET_IID...
        for tag_name in deleted_tags:
            self.addTagChecks(["tag:onRemove:"+str(tag_name)], data_target)
        for tag_name in added_tags:
            self.addTagChecks(["tag:onAdd:"+str(tag_name)], data_target)
            self.addTagDefects(lk_new_tags[tag_name], data_target)#, ObjectId(self.getId()), target_type
        tags_data = [tag.getData() for tag in tags]
        dbclient.updateInDb(self.pentest, "tags", {"item_id": ObjectId(self.getId())}, {"$set":{"tags":tags_data, "date": datetime.now(), "item_id":ObjectId(self.getId()), "item_type":target_type}}, upsert=True)
        return True

    def updateInfos(self, newInfos: Dict[str, Any]) -> None:
        """
        Change all infos stored in self.infos with the given new ones and update the database.

        Args:
            newInfos (Dict[str, Any]): A new dictionary of custom information.
        """
        if "" in newInfos:
            del newInfos[""]
        self.infos.update(newInfos)
        dbclient = DBClient.getInstance()
        dbclient.updateInDb(self.pentest, self.__class__.coll_name, {"_id":ObjectId(self.getId())}, {"$set":{"infos":self.infos}})

    def getId(self) -> ObjectId:
        """
        Returns the id of this element.

        Returns:
            ObjectId: The id of this element.
        """
        return ObjectId(self._id)

    def __str__(self) -> str:
        """
        Magic method to convert an element to a string

        Returns:
            str: A string representation of this element. (by default class:id)
        """
        return str(self.__class__) +":"+str(self._id)

    def __repr__(self) -> str:
        """
        Magic method to convert an element to a string for print

        Returns:
            str: A string representation of this element. (by default class:id)
        """
        return str(self)

    @classmethod
    def add_tag_defects(cls, pentest: str, tag: Tag, target_data: Dict[str, Any]) -> None:
        """
        Adds defects associated with a given tag to the target data.

        Args:
            pentest (str): The name of the pentest.
            tag (Tag): The tag associated with the defects.
            target_data (Dict[str, Any]): The target data to which the defects will be added.
        """
        from pollenisator.server.modules.cheatsheet.cheatsheet import CheckItem
        from pollenisator.core.models.defect import Defect

        checkitems = CheckItem.fetchObjects("pollenisator", {
            "defect_tags": {
                "$elemMatch": {
                    "$elemMatch": {
                        "$eq": tag.name
                    }
                }
            }
        })
        if checkitems is None:
            return
        dbclient = DBClient.getInstance()
        pentest_lang: Optional[str] = None
        pentest_lang_setting = dbclient.findInDb(pentest, "settings", {"key":"lang"}, False)
        if pentest_lang_setting is not None:
            pentest_lang = pentest_lang_setting.get("value")
        for check in checkitems:
            for defect_tag in check.defect_tags:
                if defect_tag[0] == tag.name:
                    defect_to_add = defect_tag[1]
                    defect = Defect.fetchObject("pollenisator", {"_id":ObjectId(defect_to_add)})
                    if defect is not None:
                        defect = cast(Defect, defect)
                        if pentest_lang is not None and pentest_lang != "" and pentest_lang != defect.language:
                            continue
                        new_defect_data = defect.getData()
                        new_defect_data["ip"] = target_data.get("target_data", {}).get("ip", "")
                        new_defect_data["port"] = target_data.get("target_data", {}).get("port", "")
                        new_defect_data["proto"] = target_data.get("target_data", {}).get("proto", "")
                        new_defect_data["target_id"] = target_data.get("target_id")
                        new_defect_data["target_type"] = target_data.get("target_type")
                        new_defect_data["notes"] = tag.notes
                        newDefect = Defect(pentest, new_defect_data)
                        newDefect.addInDb()

    @classmethod
    def add_tag_check(cls, pentest: str, lvls: List[str], infos: Dict[str, Any]) -> None:
        """
        Adds check items associated with a given level to the information.

        Args:
            pentest (str): The name of the pentest.
            lvls (List[str]): The levels associated with the check items.
            infos (Dict[str, Any]): The information to which the check items will be added.
        """
        from pollenisator.server.modules.cheatsheet.checkinstance import CheckInstance
        dbclient = DBClient.getInstance()
        search = {"lvl":{"$in": lvls}}
        pentest_type = dbclient.findInDb(pentest, "settings", {"key":"pentest_type"}, False)
        if pentest_type is not None:
            search["pentest_types"] = pentest_type["value"]
        # query mongo db commands collection for all commands having lvl == network or domain
        from pollenisator.server.modules.cheatsheet.cheatsheet import CheckItem
        checkitems = CheckItem.fetchObjects("pollenisator", search)
        if checkitems is None:
            return
        for check in checkitems:
            CheckInstance.createFromCheckItem(pentest, check, ObjectId(infos.get("target_iid")), str(infos.get("target_type", "")), infos)

    def addTagChecks(self, lvls: List[str], infos: Dict[str, Any]) -> None:
        """
        Adds check items associated with a given level to the information.

        Args:
            lvls (List[str]): The levels associated with the check items.
            infos (Dict[str, Any]): The information to which the check items will be added.
        """
        return self.__class__.add_tag_check(self.pentest, lvls, infos)

    def addTagDefects(self, tag: Tag, target_data: Dict[str, Any]) -> None:
        """
        Adds defects associated with a given tag to the target data.

        Args:
            tag (Tag): The tag associated with the defects.
            target_data (Dict[str, Any]): The target data to which the defects will be added.
        """
        return self.__class__.add_tag_defects(self.pentest, tag, target_data)

    @classmethod
    def apply_retroactively_custom(cls, pentest: str, check_item_any: Any) -> None:
        """
        Applies a given check item retroactively to all elements tagged with the same tag as the check item.

        Args:
            pentest (str): The name of the pentest.
            check_item (CheckItem): The check item to be applied.
        """
        from pollenisator.server.modules.cheatsheet.cheatsheet import CheckItem
        check_item = cast(CheckItem, check_item_any)
        dbclient = DBClient.getInstance()
        if check_item.lvl.startswith("tag:onAdd:"):
            tag_test = check_item.lvl.split(":")[2]
            taggeds = dbclient.findInDb(pentest, "tags", {}, True)
            for tagged in taggeds:
                for tag_name in tagged.get("tags", []):
                    if not isinstance(tag_name, str):
                        tag_name = tag_name[0]
                    if tag_name != tag_test:
                        continue
                    element_cls = cls.classFactory(tagged.get("item_type",""))
                    if element_cls is None:
                        raise ValueError("Element class not found for type "+str(tagged.get("item_type","")))
                    item_tagged = element_cls.fetchObject(pentest, {"_id":ObjectId(tagged.get("item_id"))})
                    if item_tagged is None:
                        continue
                    infos = {"target_iid":ObjectId(item_tagged.getId()), "target_type":tagged.get("item_type",""), "tags":tagged, "target_data":item_tagged.getData()}
                    cls.add_tag_check(pentest, [check_item.lvl], infos)

    @classmethod
    def getTriggers(cls) -> List[str]:
        """
        Returns a list of triggers associated with this class.

        Returns:
            List[str]: A list of triggers. For this class, the triggers are "tag:onAdd:str" and "tag:onRemove:str".
        """
        return ["tag:onAdd:str", "tag:onRemove:str"]

    @classmethod
    def getCommandVariables(cls) -> List[str]:
        """
        Returns the command variables associated with this class.

        Returns:
            List[str]: A dictionary of command variables.
        """
        return cls.command_variables
