"""Element parent Model. Common ground for every model"""
from bson.objectid import ObjectId
from abc import ABCMeta, abstractmethod
from datetime import datetime
from typing import Any, Dict, Generator, List, Optional, Union, cast
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.components.tag import Tag
from pollenisator.server.modules.activedirectory.computer_infos import ComputerInfos


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
# Create a new metaclass that inherits from both ABCMeta and the custom MetaPlugin
class AbstractMetaElement(ABCMeta, MetaElement):
    pass


class Element(metaclass=AbstractMetaElement):
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

    @abstractmethod
    def initialize(self, *args, **kwargs) -> 'Element':
        pass

    @abstractmethod
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
    def fetchObjects(cls, pentest: str, pipeline: Dict[str, Any]) -> Generator[ 'Element', None, None]:
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
    def fetchInScopeObjects(cls, pentest: str, pipeline: Dict[str, Any]) -> Generator['Element', None, None]:
        """
        Fetch many elements from database and hcecks if in scopes and return a Cursor to iterate over model objects.

        Args:
            pentest (str): The name of the pentest.
            pipeline (Dict[str, Any]): A MongoDB search pipeline.

        Returns:
            Generator['Element', None, None]: A cursor to iterate on model objects.
        """
        return cls.fetchObjects(pentest, pipeline) # default case does not have scope, so just fetch all

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
        if newTag.name in [tag.name for tag in tags]:
            return
        dbclient = DBClient.getInstance()
        for group in dbclient.getTagsGroups():
            self.handle_tag_group(tags, newTag, group, override)
        tags.append(newTag)
        self.setTags(tags)
        dbclient.doRegisterTag(self.pentest, newTag)

    def handle_tag_group(self, tags: List[Tag], newTag: Tag, group: List[str], override: bool) -> None:
        """
        Handle the addition of a new tag by checking for conflicts within a group of tags.
        """
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

    def delTag(self, tag: str) -> None:
        """Delete the given tag name in model if it has it
        Args:
            tag (str): a string describing a tag name.
        """
        dbclient = DBClient.getInstance()
        dbclient.updateInDb(self.pentest, "tags", {"item_id": ObjectId(self.getId())}, {"$pull":{"tags":{"name":tag}}})

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
        if isinstance(self.infos, ComputerInfos):
            dbclient.updateInDb(self.pentest, self.__class__.coll_name, {"_id":ObjectId(self.getId())}, {"$set":{"infos":self.infos.getData()}})
        else:
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

        
        defects_tags = DBClient.getInstance().findInDb("pollenisator", "defect_tags", {"tag_name": tag.name}, True)
        if defects_tags is None:
            return
        # Get pentest language setting once
        pentest_language = cls._get_pentest_language(pentest)
        
        # Process each check item and its associated defects
        for defect_tag in defects_tags:
            cls._process_tags_defects(pentest, tag, target_data, defect_tag, pentest_language)

    @classmethod
    def _get_pentest_language(cls, pentest: str) -> Optional[str]:
        """
        Retrieves the language setting for the given pentest.
        
        Args:
            pentest (str): The name of the pentest.
            
        Returns:
            Optional[str]: The language setting or None if not found.
        """
        dbclient = DBClient.getInstance()
        lang_setting = dbclient.findInDb(pentest, "settings", {"key": "lang"}, False)
        return lang_setting.get("value") if lang_setting else None

    @classmethod
    def _process_tags_defects(cls, pentest: str, tag: Tag, target_data: Dict[str, Any], 
                                  defect_tag: Dict[str, Any], pentest_language: Optional[str]) -> None:
        """
        Processes defects for a tag by checking if the defect tag matches the tag name and creating new defects as needed.
        
        Args:
            pentest (str): The name of the pentest.
            tag (Tag): The tag associated with the defects.
            target_data (Dict[str, Any]): The target data to which the defects will be added.
            defect_tag: a defect-tag association
            pentest_language (Optional[str]): The pentest language setting.
        """
        from pollenisator.core.models.defect import Defect
        
        if not cls._is_matching_defect_tag(defect_tag.get("tag_name",""), tag.name):
            return
            
        defect_common_translation_id = defect_tag.get("defect_common_translation_id", "")
        defects_translations = Defect.fetchObjects("pollenisator", {"common_translation_id": defect_common_translation_id})
        if defects_translations is None:
            return
        english_defect = None
        for defect in cast(Generator[Defect, None, None], defects_translations):
        # Skip defect if language doesn't match pentest language
            if cls._should_include_defect(defect, pentest_language):
                cls._create_new_defect(pentest, tag, target_data, defect)
                return # one translation per tag is enough, we can stop after the first match
            else:
                if defect.language == "en":
                    english_defect = defect
        # If no defect matches the pentest language but an English translation exists, create a defect based on the English translation
        if english_defect is not None: # fallback
            cls._create_new_defect(pentest, tag, target_data, english_defect)
        return
        
        

    @classmethod
    def _is_matching_defect_tag(cls, defect_tag: List[str], tag_name: str) -> bool:
        """
        Checks if a defect tag matches the given tag name.
        
        Args:
            defect_tag (List[str]): The defect tag tuple [tag_name, defect_id].
            tag_name (str): The tag name to match.
            
        Returns:
            bool: True if the defect tag matches, False otherwise.
        """
        if isinstance(defect_tag, str):
            return defect_tag == tag_name
        return len(defect_tag) >= 2 and defect_tag[0] == tag_name

    @classmethod
    def _should_include_defect(cls, defect: Any, pentest_language: Optional[str]) -> bool:
        """
        Determines if a defect should be included based on language matching.
        
        Args:
            defect: The defect object to check.
            pentest_language (Optional[str]): The pentest language setting.
            
        Returns:
            bool: True if the defect should be included, False otherwise.
        """
        if pentest_language is None or pentest_language == "":
            return True
        
        return defect.language == pentest_language

    @classmethod
    def _create_new_defect(cls, pentest: str, tag: Tag, target_data: Dict[str, Any], template_defect: Any) -> None:
        """
        Creates a new defect based on a template defect and target data.
        
        Args:
            pentest (str): The name of the pentest.
            tag (Tag): The tag associated with the defect.
            target_data (Dict[str, Any]): The target data for the new defect.
            template_defect: The template defect to base the new defect on.
        """
        from pollenisator.core.models.defect import Defect
        
        new_defect_data = template_defect.getData()
        target_info = target_data.get("target_data", {})
        
        # Update defect data with target-specific information
        new_defect_data.update({
            "ip": target_info.get("ip", ""),
            "port": target_info.get("port", ""),
            "proto": target_info.get("proto", ""),
            "target_id": target_data.get("target_id"),
            "target_type": target_data.get("target_type"),
            "notes": tag.notes
        })
        
        new_defect = Defect(pentest, new_defect_data)
        new_defect.addInDb()

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
            CheckInstance.createFromCheckItem(pentest, check, ObjectId(infos.get("target_iid")), str(infos.get("target_type", "")), infos=infos)

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
        
        # Only process tag:onAdd triggers
        if not check_item.lvl.startswith("tag:onAdd:"):
            return
            
        # Extract tag name from level string (format: "tag:onAdd:tagname")
        tag_target = cls._extract_tag_from_level(check_item.lvl)
        if not tag_target:
            return
            
        dbclient = DBClient.getInstance()
        tagged_items = dbclient.findInDb(pentest, "tags", {}, True)
        
        if not tagged_items:
            return
            
        for tagged_item in tagged_items:
            cls._process_tagged_item(pentest, tagged_item, tag_target, check_item.lvl)
    
    @classmethod
    def _extract_tag_from_level(cls, level: str) -> Optional[str]:
        """
        Extracts the tag name from a level string in format "tag:onAdd:tagname".
        
        Args:
            level (str): The level string to parse.
            
        Returns:
            Optional[str]: The extracted tag name, or None if parsing fails.
        """
        parts = level.split(":")
        return parts[2] if len(parts) >= 3 else None
    
    @classmethod
    def _process_tagged_item(cls, pentest: str, tagged_item: Dict[str, Any], 
                           target_tag: str, check_level: str) -> None:
        """
        Processes a single tagged item, applying checks if it matches the target tag.
        
        Args:
            pentest (str): The name of the pentest.
            tagged_item (Dict[str, Any]): The tagged item from database.
            target_tag (str): The tag we're looking for.
            check_level (str): The check level to apply.
        """
        tag_names = cls._extract_tag_names(tagged_item)
        
        if target_tag not in tag_names:
            return
            
        # Get the element class and fetch the tagged object
        element_cls = cls._get_element_class(tagged_item)
        if element_cls is None:
            return
            
        item_tagged = cls._fetch_tagged_object(pentest, element_cls, tagged_item)
        if item_tagged is None:
            return
            
        # Apply the check to the tagged item
        cls._apply_check_to_item(pentest, tagged_item, item_tagged, check_level)
    
    @classmethod
    def _extract_tag_names(cls, tagged_item: Dict[str, Any]) -> List[str]:
        """
        Extracts tag names from a tagged item, handling both string and tuple formats.
        
        Args:
            tagged_item (Dict[str, Any]): The tagged item from database.
            
        Returns:
            List[str]: List of tag names.
        """
        tag_names = []
        for tag_data in tagged_item.get("tags", []):
            if isinstance(tag_data, str):
                tag_names.append(tag_data)
            elif isinstance(tag_data, (list, tuple)) and len(tag_data) > 0:
                # Handle tuple/list format where tag name is first element
                tag_names.append(tag_data[0])
            elif isinstance(tag_data, dict) and "name" in tag_data:
                tag_names.append(tag_data["name"])
        return tag_names
    
    @classmethod
    def _get_element_class(cls, tagged_item: Dict[str, Any]) -> Optional['Element']:
        """
        Gets the element class for the tagged item.
        
        Args:
            tagged_item (Dict[str, Any]): The tagged item from database.
            
        Returns:
            Optional['Element']: The element class, or None if not found.
        """
        item_type = tagged_item.get("item_type", "")
        element_cls = cls.classFactory(item_type)
        
        if element_cls is None:
            raise ValueError(f"Element class not found for type '{item_type}'")
            
        return element_cls
    
    @classmethod
    def _fetch_tagged_object(cls, pentest: str, element_cls: 'Element', 
                           tagged_item: Dict[str, Any]) -> Optional['Element']:
        """
        Fetches the actual object that was tagged.
        
        Args:
            pentest (str): The name of the pentest.
            element_cls ('Element'): The class of the element to fetch.
            tagged_item (Dict[str, Any]): The tagged item from database.
            
        Returns:
            Optional['Element']: The fetched object, or None if not found.
        """
        item_id = tagged_item.get("item_id")
        if not item_id:
            return None
            
        return element_cls.fetchObject(pentest, {"_id": ObjectId(item_id)})
    
    @classmethod
    def _apply_check_to_item(cls, pentest: str, tagged_item: Dict[str, Any], 
                           item_tagged: 'Element', check_level: str) -> None:
        """
        Applies the check to a specific tagged item.
        
        Args:
            pentest (str): The name of the pentest.
            tagged_item (Dict[str, Any]): The tagged item from database.
            item_tagged ('Element'): The actual tagged object.
            check_level (str): The check level to apply.
        """
        target_info = {
            "target_iid": ObjectId(item_tagged.getId()),
            "target_type": tagged_item.get("item_type", ""),
            "tags": tagged_item,
            "target_data": item_tagged.getData()
        }
        
        cls.add_tag_check(pentest, [check_level], target_info)

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
