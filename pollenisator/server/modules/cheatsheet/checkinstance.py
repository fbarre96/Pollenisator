"""
Instanciation of a checkItem, with a target and a status
"""
from typing import Callable, Generator, Iterable, List, Optional, Dict, Any, Set, Union, Tuple, cast
from typing_extensions import TypedDict
from bson import ObjectId
from pymongo import UpdateOne
from pymongo.cursor import Cursor
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.components.utils import detect_objectid
from pollenisator.core.models.command import Command
from pollenisator.core.models.element import Element
import pollenisator.core.models.tool as tool
from pollenisator.server.modules.cheatsheet.cheatsheet import CheckItem
from pollenisator.server.permission import permission
from pollenisator.core.components.logger_config import logger

ErrorStatus = Tuple[str, int]
CheckInstanceInsertResult = TypedDict('CheckInstanceInsertResult', {'res': bool, 'iid': ObjectId})
BodyMultiChangeOfStatus = TypedDict('BodyMultiChangeOfStatus', {'status': str, 'iids': List[str]})
BodyQueueCheckInstances = TypedDict('BodyQueueCheckInstances', {'iids': List[str], 'priority': int, 'force': bool})

class CheckInstance(Element):
    """
    Represents a check instance object to be run on designated targets.

    Attributes:
        coll_name: collection name in pollenisator or pentest database
    """
    coll_name = 'checkinstances'

    def __init__(self, pentest: str, valuesFromDb: Optional[Dict[str, Any]] = None, lookupTarget:bool =True) -> None:
        """
        Initialize a CheckInstance object.

        Args:
            pentest (str): The name of the pentest.
            valuesFromDb (Optional[Dict[str, Any]], optional): A dictionary with values from the database. Defaults to None.

        """
        if valuesFromDb is None:
            valuesFromDb = {}
        super().__init__(pentest, valuesFromDb)
        self.status = ""
        self.initialize(valuesFromDb.get("check_iid", None), valuesFromDb.get("target_iid", None), valuesFromDb.get(
            "target_type", ""), valuesFromDb.get("status", ""), valuesFromDb.get("notes", ""), valuesFromDb.get("target_repr", None), lookupTarget=lookupTarget)

    def initialize(self, check_iid: Optional[ObjectId], target_iid: Optional[ObjectId], target_type: str, status: str, notes: str, target_repr: Optional[str]=None, lookupTarget: bool= True) -> 'CheckInstance':
        """
        Initialize a CheckInstance object.

        Args:
            check_iid (Optional[ObjectId]): The id of the check.
            target_iid (Optional[ObjectId]): The id of the target.
            target_type (str): The type of the target.
            status (str): The status of the check instance.
            notes (str): The notes for the check instance.
            target_repr (Optional[str]): The representation of the target.

        Returns:
            CheckInstance: The initialized CheckInstance object.
        """
        self.type = "checkinstance"
        self.check_iid = ObjectId(check_iid) if check_iid else None
        self.target_iid = ObjectId(target_iid) if target_iid else None
        self.target_type = target_type
        self.status = status
        self.notes = notes
        self.target_repr = target_repr # define it 
        if lookupTarget and (target_type != "" and target_iid is not None):
            self.target_repr = self.getTargetRepresentation() # populate it if not initialized
        if not isinstance(self.target_repr, str) and not isinstance(self.target_repr, type(None)):
            self.target_repr = None
            raise ValueError("target_repr must be a string or None")

        return self

    @classmethod
    def getSearchableTextAttribute(cls) -> List[str]:
        """
        Get the attributes that can be used for searching.

        Returns:
            List[str]: A list of attribute names.
        """
        return ["title", "category", "lvl"] # will load on checktitems attribute

    @classmethod
    def fetchObjects(cls, pentest: str, pipeline: Dict[str, Any]) -> Generator['CheckInstance', None, None]:
        """
        Fetch many commands from database and return a Cursor to iterate over model objects.

        Args:
            pentest (str): The name of the pentest.
            pipeline (Dict[str, Any]): A Mongo search pipeline.

        Returns:
            Generator[CheckInstance]: A cursor to iterate on model objects.
        """
        dbclient = DBClient.getInstance()
        pipeline["type"] = "checkinstance"
        ds = dbclient.findInDb(pentest, cls.coll_name, pipeline, True)
        if ds is None:
            return None
        for d in ds:
            # disabling this error as it is an abstract function
            yield CheckInstance(pentest, d)  #  pylint: disable=no-value-for-parameter

    @classmethod
    def fetchObject(cls, pentest: str, pipeline: Dict[str, Any]) -> Optional['CheckInstance']:
        """
        Fetch a single command from the database and return a CheckInstance object.

        Args:
            pentest (str): The name of the pentest.
            pipeline (Dict[str, Any]): A Mongo search pipeline.

        Returns:
            Optional[CheckInstance]: A CheckInstance object if found, None otherwise.
        """
        dbclient = DBClient.getInstance()
        pipeline["type"] = "checkinstance"
        d = dbclient.findInDb(pentest, cls.coll_name, pipeline, False)
        if d is None:
            return None
        return CheckInstance(pentest, d)
    
    # def get_children(self) -> Dict[str, List[Dict[str, Any]]]:
    #     """
    #     Returns the children of this Port.

    #     Returns:
    #         Dict[str, List[Dict[str, Any]]]: A list of dictionaries containing the children of this Port.
    #     """
    #     children: Dict[str, List[Dict[str, Any]]] = {"tools":[]}
    #     tools = tool.Tool.fetchObjects(self.pentest, {"check_iid": ObjectId(self.getId())})
    #     if tools is not None:
    #         for tool in tools:
    #             tool = cast(tool.Tool, tool)
    #             tool_data = tool.getData()
    #             children["tools"].append(tool_data)

    #     return children

    def getTargetData(self) -> Dict[str, Any]:
        """
        Get the target data associated with this CheckInstance.
        
        Returns:
            Dict[str, Any]: The target data.
        """
        target_class = Element.classFactory(self.target_type)
        if target_class is None:
            logger.error("Invalid target type used : %s", self.target_type)
            return {}
        dbclient = DBClient.getInstance()
        return dbclient.findInDb(self.pentest, target_class.coll_name, {
                                        "_id": ObjectId(self.target_iid)}, False)

    def getCheckItem(self) -> Optional['CheckItem']:
        """
        Get the CheckItem associated with this CheckInstance.

        Returns:
            CheckItem: The CheckItem instance associated with this CheckInstance's check iid.
        """
        check_item: Optional[CheckItem] = CheckItem.fetchObject("pollenisator", {"_id": ObjectId(self.check_iid)})
        return check_item

    def getData(self) -> Dict[str, Any]:
        """
        Get the data of the CheckInstance object.

        Returns:
            Dict[str, Any]: A dictionary containing the data of the CheckInstance object.
        """
        return {"_id": self._id, "type": self.type, "check_iid": self.check_iid, "target_iid": self.target_iid, "target_type": self.target_type, "parent": self.parent, "status": self.status, "notes": self.notes, "target_repr": self.target_repr}

    def addInDb(self, checkItem: Optional[CheckItem] = None, toolInfos: Optional[Dict[str, Any]] = None) -> Union[CheckInstanceInsertResult, ErrorStatus]:
        """
        Add the CheckInstance object in the database.

        Args:
            checkItem (Optional[Any], optional): The check item to add. Defaults to None.
            toolInfos (Optional[Dict[str, Any]], optional): The tool information to add. Defaults to None.

        Returns:
            Union[CheckInstanceInsertResult, ErrorStatus]: The result of the insertion.
        """
        if toolInfos is None:
            toolInfos = {}
        data = self.getData()
        if "_id" in data:
            del data["_id"]
        if "type" in data:
            del data["type"]
        dbclient = DBClient.getInstance()
        data["type"] = "checkinstance"
        # CHECK EXISTING
        data["check_iid"] = None if data.get("check_iid") is None else ObjectId(data["check_iid"])
        data["target_iid"] = None if data.get("target_iid") is None else ObjectId(data["target_iid"])
        existing = CheckInstance.fetchObject(self.pentest, {"check_iid": data["check_iid"], "target_iid": data["target_iid"], "target_type": data.get("target_type", "")})
        if existing is not None:
            return {"res": False, "iid": existing.getId()}
        # IF NOT EXISTING INSERT
        ins_result = dbclient.insertInDb(
            self.pentest, CheckInstance.coll_name, data, notify=True)
        iid = ins_result.inserted_id
        self._id = iid
        if checkItem is None or ObjectId(checkItem.getId()) != ObjectId(data["check_iid"]):
            checkItem = CheckItem.fetchObject("pollenisator", {"_id": ObjectId(data["check_iid"])})

        target_class = Element.classFactory(data["target_type"])
        if target_class is None:
            return "Invalid target type", 404
        target = dbclient.findInDb(self.pentest, target_class.coll_name, {
                                        "_id": ObjectId(data["target_iid"])}, False)
        if target is None:
            return "Invalid target, not found", 404
        if checkItem is None:
            return "Check Item not found", 404
        for command in checkItem.commands:
            command_pentest = Command.fetchObject(self.pentest, {"original_iid": ObjectId(command)})
            if command_pentest is not None:
                tool_model = tool.Tool(self.pentest)
                tool_model.initialize(ObjectId(command_pentest.getId()), ObjectId(iid), target.get("wave", ""), None, target.get("scope", ""), target.get("ip", ""), target.get("port", ""),
                                            target.get("proto", ""), checkItem.lvl, infos=toolInfos)
                tool_model.addInDb(update_check=False)
        if ins_result is None:
            return {"res": False, "iid": iid}
        return {"res": True, "iid": iid}

    def deleteFromDb(self) -> int:
        """
        Delete the CheckInstance from the database.

        Returns:
            int: The number of deleted CheckInstances.
        """
        dbclient = DBClient.getInstance()
        dbclient.deleteFromDb(self.pentest, 'tools', {"check_iid": self.getId()}, many=True, notify=True)
        res = dbclient.deleteFromDb(self.pentest, CheckInstance.coll_name, {
                                        "_id": ObjectId(self.getId())}, many=False, notify=True)
        if res is None:
            return 0
        return res
    
    @classmethod
    def bulk_insert_for(cls, pentest: str, targets: Iterable, targets_type: str, lvls: List[str], f_get_impacted_targets: Optional[Callable] = None, toolInfos: Optional[Dict[str, Any]] = None) -> Optional[List['CheckInstance']]:
        """
        Bulk insert check instances for given targets and levels.

        Args:
            pentest (str): The name of the pentest.
            targets (Iterable): The targets for which to insert check instances.
            targets_type (str): The type of the targets.
            lvls (List[str]): The levels for which to insert check instances.
            f_get_impacted_targets (Optional[Callable], optional): A function to get impacted targets. Defaults to None.
            toolInfos (Optional[Dict[str, Any]], optional): The tool information to add. Defaults to None.

        Returns:
            Optional[List[CheckInstance]]: A list of inserted CheckInstance objects, None if no checks were added.
        """
        # Get pentest type setting
        dbclient = DBClient.getInstance()
        pentest_type_setting = dbclient.findInDb(pentest, "settings", {"key": "pentest_type"}, False)
        pentest_type = None if pentest_type_setting is None else pentest_type_setting.get("value", None)
        
        # Fetch relevant check items
        checks = CheckItem.fetchObjects("pollenisator", {"lvl": {"$in": lvls}, "pentest_types": pentest_type})
        if checks is None:
            return None
            
        # Convert targets to list for multiple iterations
        targets_list = list(targets)
        
        # Build lookup tables for checks and commands
        checks_lkp = {str(check.getId()): check for check in checks}
        commands_pentest = Command.fetchObjects(pentest, {})
        commands_lkp = {str(command.original_iid): command for command in commands_pentest}
        
        # Prepare data structures
        checks_to_add = []
        check_command_lkp: Dict[str, List[Command]]  = {}
        
        # Create check instances and build command lookup
        for check_item in checks_lkp.values():
            # Determine impacted targets
            if callable(f_get_impacted_targets):
                impacted_targets = f_get_impacted_targets(check_item, targets_list)
            else:
                impacted_targets = targets_list
                
            # Create check instances for each target
            for target in impacted_targets:
                check_instance = CheckInstance(pentest).initialize(
                    ObjectId(check_item.getId()), 
                    ObjectId(target.getId()), 
                    targets_type, 
                    "", 
                    ""
                )
                checks_to_add.append(check_instance)
                
            # Build command lookup for this check item
            check_item_id = str(check_item.getId())
            check_command_lkp[check_item_id] = []
            
            for command_id in check_item.commands:
                command = commands_lkp.get(str(command_id))
                if command is not None:
                    check_command_lkp[check_item_id].append(command)
        
        if not checks_to_add:
            return None
            
        # Prepare data for bulk insertion
        insertion_data = {}
        check_keys = set()
        or_conditions = []
        
        for check_instance in checks_to_add:
            hashable_key = check_instance.getHashableDbKey()
            data = check_instance.getData()
            
            # Prepare data for insertion
            if "_id" in data:
                del data["_id"]
            data["type"] = "checkinstance"
            
            insertion_data[hashable_key] = data
            check_keys.add(hashable_key)
            or_conditions.append(check_instance.getDbKey())
        
        # Create index and filter existing checks
        dbclient.create_index(pentest, "checkinstances", [("check_iid", 1), ("target_iid", 1), ("target_type", 1)])
        existing_checks = CheckInstance.fetchObjects(pentest, {"$or": or_conditions})
        existing_keys = set() if existing_checks is None else {check.getHashableDbKey() for check in existing_checks}
        
        # Determine new checks to insert
        keys_to_add = check_keys - existing_keys
        documents_to_insert = [insertion_data[key] for key in keys_to_add]
        
        if not documents_to_insert:
            return None
            
        # Insert new check instances
        insert_result = dbclient.insertManyInDb(pentest, CheckInstance.coll_name, documents_to_insert)
        inserted_ids = insert_result.inserted_ids
        
        # Retrieve inserted check instances in batches
        checks_inserted = cls._retrieve_inserted_checks_in_batches(pentest, inserted_ids)
        
        if not checks_inserted:
            return None
            
        # Create associated tools
        tools_to_add = cls._create_tools_for_check_instances(
            pentest, checks_inserted, targets_list, checks_lkp, check_command_lkp, toolInfos
        )
        
        if tools_to_add:
            tool.Tool.bulk_insert(pentest, tools_to_add)

        return checks_inserted
    
    @classmethod
    def _retrieve_inserted_checks_in_batches(cls, pentest: str, inserted_ids: List[ObjectId], batch_size: int = 1000000) -> List['CheckInstance']:
        """
        Retrieve inserted check instances in batches to handle large datasets.
        
        Args:
            pentest (str): The name of the pentest.
            inserted_ids (List[ObjectId]): List of inserted check instance IDs.
            batch_size (int): Size of each batch for retrieval.
            
        Returns:
            List[CheckInstance]: List of retrieved check instances.
        """
        checks_inserted = []
        total_ids = len(inserted_ids)
        current_offset = 0
        
        while current_offset < total_ids:
            batch_end = min(current_offset + batch_size, total_ids)
            batch_ids = inserted_ids[current_offset:batch_end]
            
            batch_checks = CheckInstance.fetchObjects(pentest, {"_id": {"$in": batch_ids}})
            if batch_checks is not None:
                checks_inserted.extend([cast(CheckInstance, check) for check in batch_checks])
                
            current_offset += batch_size
            
        return checks_inserted
    
    @classmethod
    def _create_tools_for_check_instances(cls, pentest: str, checks_inserted: List['CheckInstance'], targets_list: List, 
                                        checks_lkp: Dict[str, CheckItem], check_command_lkp: Dict[str, List[Command]], 
                                        toolInfos: Optional[Dict[str, Any]]) -> List:
        """
        Create tools for the inserted check instances.
        
        Args:
            pentest (str): The name of the pentest.
            checks_inserted (List[CheckInstance]): List of inserted check instances.
            targets_list (List): List of targets.
            checks_lkp (Dict[str, CheckItem]): Lookup table for check items.
            check_command_lkp (Dict[str, List[Command]]): Lookup table for commands by check item.
            toolInfos (Optional[Dict[str, Any]]): Additional tool information.
            
        Returns:
            List: List of tools to be added.
        """
        tools_to_add = []
        
        for check_instance in checks_inserted:
            check_item_id = str(check_instance.check_iid)
            check_item = checks_lkp.get(check_item_id)
            
            # Determine level
            level = check_item.lvl if check_item else "unknown"
            
            # Get commands for this check item
            commands = check_command_lkp.get(check_item_id, [])
            
            # Create tools for each command and target combination
            for command in commands:
                for target in targets_list:
                    target_data = target.getData()
                    
                    tool_model = tool.Tool(pentest)
                    tool_model.initialize(
                        ObjectId(command.getId()),
                        ObjectId(check_instance.getId()),
                        target_data.get("wave", ""),
                        command.name,
                        target_data.get("scope", ""),
                        target_data.get("ip", ""),
                        target_data.get("port", ""),
                        target_data.get("proto", ""),
                        level,
                        infos=toolInfos
                    )
                    tools_to_add.append(tool_model)
        
        return tools_to_add


    @classmethod
    def bulk_queue(cls, pentest: str, checks_iids: List[ObjectId], priority: int, force: bool = False) -> None:
        """
        Queue multiple checks for a given pentest.

        Args:
            pentest (str): The name of the pentest.
            checks_iids (List[ObjectId]): The ids of the checks to queue.
            priority (int): The priority of the checks.
            force (bool, optional): Whether to force the queuing of the checks. Defaults to False.
        """
        dbclient = DBClient.getInstance()
        queue_db = dbclient.findInDb(pentest, "autoscan", {"type":"queue"}, False)
        if queue_db is None:
            queue = list()
            dbclient.insertInDb(pentest, "autoscan", {"type":"queue", "tools":[]})
        else:
            queue = list(queue_db.get("tools", []))
        index = len(queue)
        for i, tool_info in enumerate(queue):
            if priority > tool_info.get("priority", 0):
                index = i
                break
        tools = dbclient.findInDb(pentest, "tools", {"check_iid":{"$in":checks_iids}, "status":{"$ne":"done"}}, True)
        queue_final = queue[:index] + [{"iid":tool_data["_id"], "priority":priority, "force":force} for tool_data in tools] + queue[index:]
        dbclient.updateInDb(pentest, "autoscan", {"type":"queue"}, {"$set":{"tools":queue_final}})

    @classmethod
    def createFromCheckItem(cls, pentest: str, checkItem: 'CheckItem', target_iid: ObjectId, target_type: str, target_repr: Optional[str]=None, infos: Optional[Dict[str, Any]] = None) -> Union[CheckInstanceInsertResult, ErrorStatus]:
        """
        Create a CheckInstance from a CheckItem.

        Args:
            pentest (str): The name of the pentest.
            checkItem (CheckItem): The CheckItem to create the CheckInstance from.
            target_iid (ObjectId): The id of the target.
            target_type (str): The type of the target.
            target_repr (Optional[str], optional): The representation of the target. Defaults to None.
            infos (Optional[Dict[str, Any]], optional): Additional information. Defaults to {}.

        Returns:
            Dict[str, Any]: The result of the insertion of the CheckInstance into the database.
        """
        infos = {} if infos is None else infos
        checkinstance = CheckInstance(pentest, {}, lookupTarget=False).initialize(ObjectId(
            checkItem.getId()), ObjectId(target_iid), target_type, "", "", target_repr)
        return checkinstance.addInDb(checkItem=checkItem, toolInfos=infos)

    def update(self) -> Union[ErrorStatus, bool]:
        """
        Update the CheckInstance in the database.

        Returns:
            Union[ErrorStatus, bool]: The result of the update operation.
        """
        res: Union[ErrorStatus, bool] = update(self.pentest, self._id, self.getData())
        return res

    def getDbKey(self) -> Dict[str, Any]:
        """
        Return a database composed key for the CheckInstance.

        Returns:
            Dict[str, Any]: The database key for the CheckInstance.
        """
        return {"check_iid": self.check_iid, "target_iid": self.target_iid, "target_type": self.target_type}

    def getHashableDbKey(self) -> Tuple[str, ...]:
        """
        Return a Hashable database composed key for the CheckInstance.

        Returns:
            Tuple[str, str, str]: The database key for the CheckInstance.
        """
        return tuple(self.getDbKey().values())

    def getCheckInstanceInformation(self) -> Union[None, Dict[str, Any]]:
        check_item = CheckItem.fetchObject("pollenisator", {"_id": ObjectId(self.check_iid)})
        if check_item is None:
            return None
        data = self.getData()
        check_item_data = check_item.getData()
        data["check_item"] = check_item_data
        data["tools_done"] = {}
        data["tools_running"] = {}
        data["tools_not_done"] = {}
        data["tools_error"] = {}
        all_complete = True
        at_least_one = False
        total = 0
        done = 0
        dbclient = DBClient.getInstance()
        dbclient.create_index(self.pentest, "tools", [("check_iid",1)])
        tools_to_add = tool.Tool.fetchObjects(self.pentest, {"check_iid": ObjectId(self.getId())})
        if tools_to_add is not None:
            for tool_model in tools_to_add:
                running_or_done, is_done = self._add_tool_information(data, cast(tool.Tool, tool_model))
                at_least_one = at_least_one or running_or_done
                done += 1 if is_done else 0
                total += 1

        if done != total:
            all_complete = False
        if len(check_item.commands) > 0:
            if at_least_one and all_complete:
                data["status"] = "done"
            elif at_least_one and not all_complete:
                data["status"] = "running"
            else:
                data["status"] = "todo"
            data["commands"] = [command.getData() for command in Command.fetchObjects(self.pentest, {"original_iid": {"$in": [ObjectId(x) for x in check_item.commands]}})]

        else:
            data["status"] = ""
        data["forced_status"] = self.status
        data["target_repr"] = self.getTargetRepresentation()
        return data
    
    def getTargetRepresentation(self) -> str:
        """
        Get a string representation of the target.
        
        Returns:
            str: The string representation of the target.
        """
        if self.target_repr is not None:
            return self.target_repr
        # similar to getTargetRepr but for a single instance
        repres = generate_target_representations(self.pentest, {self.target_type: set([ObjectId(self.target_iid)])})
        if repres is not None:
            if repres == {}:
                return "Target not found"
            self.target_repr = list(repres.values())[0]  # save it
            self.update()  # update the db
            return self.target_repr
        return "Target not found"
    
    def _add_tool_information(self, data: Dict[str, Any], tool_model: 'tool.Tool') -> Tuple[bool, bool]:
        """
        Add tool information to the provided data dictionary.
        Args:
            data (Dict[str, Any]): The data dictionary to update.
            tool_model (tool.Tool): The tool model to extract information from.
        Returns:
            Tuple[bool, bool]: A tuple indicating if the tool is done or running and if it is done.
        """
        if "done" in tool_model.getStatus():
            data["tools_done"][str(tool_model.getId())] = tool_model.getData()
            data["tools_done"][str(tool_model.getId())]["tags"] = tool_model.getTags()
            return True, True
        elif "running" in tool_model.getStatus():
            data["tools_running"][str(
                        tool_model.getId())] = tool_model.getData()
            data["tools_running"][str(tool_model.getId())]["detailed_string"] = tool_model.getDetailedString()
            return True, False
        if "error" in tool_model.getStatus():
            data["tools_error"][str(
                        tool_model.getId())] = tool_model.getData()
        else:
            data["tools_not_done"][str(
                        tool_model.getId())] = tool_model.getData()
            command_line = tool_model.getCommandLine()
            if isinstance(command_line, tuple):
                data["tools_not_done"][str(
                            tool_model.getId())]["commandline"] = None
            else:
                data["tools_not_done"][str(
                            tool_model.getId())]["commandline"] = tool_model.getCommandLine()
            command_line_multi = tool_model.getCommandLineMulti()
            if isinstance(command_line_multi, tuple):
                data["tools_not_done"][str(
                            tool_model.getId())]["commandline_multi"] = None
            else:
                data["tools_not_done"][str(
                            tool_model.getId())]["commandline_multi"] = tool_model.getCommandLineMulti()
        return False, False
                    

    def updateInfosCheck(self, check_item: Optional['CheckItem'] = None) -> Optional[ErrorStatus]:
        """
        Update the information of the CheckInstance.

        Args:
            check_item (Optional[CheckItem], optional): The CheckItem to update the CheckInstance with. Defaults to None.

        Returns:
            Optional[ErrorStatus]: An error message if the CheckItem is not found, None otherwise.
        """
        dbclient = DBClient.getInstance()
        if check_item is None:
            check_item = CheckItem.fetchObject("pollenisator", {"_id": ObjectId(self.check_iid)})
        if check_item is None:
            return "Check item parent not found", 404
        data = self.getData()
        check_item_data = check_item.getData()
        data["check_item"] = check_item_data
        at_least_one, all_complete = self.get_tools_data(data)
        if len(check_item.commands) > 0:
            if at_least_one and all_complete:
                data["status"] = "done"
            elif at_least_one and not all_complete:
                data["status"] = "running"
            else:
                data["status"] = "todo"
        else:
            data["status"] = ""
        if data["status"] != "" and self.status != data["status"]:
            dbclient.updateInDb(self.pentest, CheckInstance.coll_name, {"_id": self.getId(), "type": "checkinstance"}, {"$set": {"status": data["status"]}}, many=False, notify=False)
            dbclient.send_notify(self.pentest, "checkinstances",  self.getId(), action="status_update", data={"status": data["status"]})
        return None

    def get_tools_data(self, data: Dict[str, Any]) -> Tuple[bool, bool]:
        data["tools_status"] = {}
        data["tools_not_done"] = {}
        data["tools_error"] = {}
        at_least_one = False
        all_complete = True
        total = 0
        done = 0
        tools_to_add = tool.Tool.fetchObjects(self.pentest, {"check_iid": ObjectId(self._id)})
        if tools_to_add is not None:
            for tool_model in tools_to_add:
                tool_model = cast(tool.Tool, tool_model)
                if "done" in tool_model.getStatus():
                    done += 1
                    at_least_one = True
                elif "running" in tool_model.getStatus():
                    at_least_one = True
                elif "error" in tool_model.getStatus():
                    data["tools_error"][str(
                        tool_model.getId())] = tool_model.getDetailedString()
                else:
                    data["tools_not_done"][str(
                        tool_model.getId())] = tool_model.getDetailedString()
                total += 1
        if done != total:
            all_complete = False
        return at_least_one, all_complete


@permission("pentester")
def insert(pentest: str, body: Dict[str, Any]) -> Union[ErrorStatus, CheckInstanceInsertResult]:
    """
    Insert a cheatsheet checkItem instance.

    Args:
        pentest (str): The name of the pentest.
        body (Dict[str, Any]): The data of the CheckInstance to insert.

    Returns:
        Union[ErrorStatus, CheckInstanceInsertResult]: An error message and status code if the pentest is "pollenisator", otherwise the result of the insertion.
    """
    if pentest == "pollenisator":
        return "Forbidden", 403
    checkinstance = CheckInstance(pentest, body)
    return checkinstance.addInDb()


@permission("pentester")
def delete(pentest: str, iid: str) -> Union[int, ErrorStatus]:
    """
    Delete a cheatsheet item.

    Args:
        pentest (str): The name of the pentest.
        iid (str): The id of the CheckInstance to delete.

    Returns:
       Union[int, ErrorStatus]: An error message and status code if the pentest is "pollenisator" or the CheckInstance is not found, 0 if the deletion was not successful, None otherwise.
    """
    if pentest == "pollenisator":
        return "Forbidden", 403
    existing = CheckInstance.fetchObject(pentest, {"_id": ObjectId(iid)})
    if existing is None:
        return "Not found", 404
    # delete tools
    return existing.deleteFromDb()



@permission("pentester")
def update(pentest: str, iid: str, body: Dict[str, Any]) -> Union[ErrorStatus, bool]:
    """
    Update a CheckInstance in the database.

    Args:
        pentest (str): The name of the pentest.
        iid (str): The id of the CheckInstance to update.
        body (Dict[str, Any]): The new data for the CheckInstance.

    Returns:
        Union[ErrorStatus, bool]: True if the update was successful, an error message otherwise.
    """
    if pentest == "pollenisator":
        return "Forbidden", 403
    checkinstance = CheckInstance(pentest, body, lookupTarget=False)
    data = {"status": checkinstance.status, "notes": checkinstance.notes}

    dbclient = DBClient.getInstance()
    existing = CheckInstance.fetchObject(pentest, {"_id": ObjectId(iid)})
    if existing is None:
        return "Not found", 404
    existing_data = existing.getData()
    existing_data |= data
    if "_id" in existing_data:
        del existing_data["_id"]
    dbclient.updateInDb(pentest, CheckInstance.coll_name, {"_id": ObjectId(
        iid), "type": "checkinstance"}, {"$set": existing_data}, many=False, notify=True)
    return True


@permission("pentester")
def getInformations(pentest: str, iid: str) -> Union[Dict[str, Any], ErrorStatus]:
    """
    Get information about a CheckInstance.

    Args:
        pentest (str): The name of the pentest.
        iid (str): The id of the CheckInstance.

    Returns:
         Union[Dict[str, Any], ErrorStatus]: The data of the CheckInstance or an error message.
    """
    inst = CheckInstance.fetchObject(pentest, {"_id": ObjectId(iid)})
    if inst is None:
        return "Not found", 404
    inst = cast(CheckInstance, inst)
    checkinfos = inst.getCheckInstanceInformation()
    if checkinfos is None:
        return "Check instance information not found", 404
    return checkinfos
    


@permission("pentester")
def getTargetRepr(pentest: str, body: List[str]) -> Dict[str, str]:
    """
    Get the representation of the target of a CheckInstance.

    Args:
        pentest (str): The name of the pentest.
        body (List[str]): The ids of the CheckInstances.

    Returns:
        Dict[str, str]: A dictionary mapping CheckInstance ids to their target's representation.
    """
    dbclient = DBClient.getInstance()
    iids_list = [ ObjectId(x) for x in body if ObjectId.is_valid(x) ]
    checkinstances = dbclient.findInDb(pentest, "checkinstances", {"_id": {"$in": iids_list}}, True)
    if isinstance(checkinstances, Cursor):
        checkinstances = list(checkinstances)
    elements = _getElementsPerType(checkinstances)
    ret = generate_target_representations(pentest, elements)
    # Update the checkinstances with the representation string
    update_operations = []
    for data in checkinstances:
        if str(data["_id"]) in ret:
            data["target_repr"] = ret[str(data["_id"])]
            update_operations.append(UpdateOne({"_id":ObjectId(data["_id"])}, {"$set":{"target_repr": data["target_repr"]}}))
    dbclient.bulk_write(pentest, "checkinstances", update_operations, notify=True)
    
    return ret

def generate_target_representations(pentest: str, elements: Dict[str, Set[ObjectId]]) -> Dict[str, str]:
    """
    Generate target representations for given elements.
    Args:
        pentest (str): The name of the pentest.
        elements (Dict[str, Set[ObjectId]]): A dictionary mapping element types to sets of ObjectIds.
    Returns:
        Dict[str, str]: A dictionary mapping CheckInstance ids to their target's representation.
    """
    ret = {}
    for element_type, element_iids in elements.items():
        class_element = Element.classFactory(element_type)
        if class_element is not None:
            elems = class_element.fetchInScopeObjects(pentest, {"_id": {"$in":list(element_iids)}})
            if not elems or elems is None:
                ret_str = "Target not found"
            else:
                for elem in elems:
                    ret_str = elem.getDetailedString()
                    ret[str(elem.getId())] = ret_str
    return ret

def _getElementsPerType(checkinstances: List[Dict[str, Any]]) -> Dict[str, Set[ObjectId]]:
    """
    Get the elements per type from a list of CheckInstances.
    Args:
        checkinstances (List[Dict[str, Any]]): A list of CheckInstances.
    Returns:
        Dict[str, Set[ObjectId]]: A dictionary mapping element types to sets of ObjectIds.
    """
    elements: Dict[str, Set[ObjectId]] = {}
    for data in checkinstances:
        if data["target_type"] not in elements:
            elements[data["target_type"]] = set()
        elements[data["target_type"]].add(ObjectId(data["target_iid"]))
    return elements

@permission("pentester")
def multiChangeOfStatus(pentest: str, body: Dict[str, BodyMultiChangeOfStatus]) -> ErrorStatus:
    """
    Change the status of multiple CheckInstances.

    Args:
        pentest (str): The name of the pentest.
        body (BodyMultiChangeOfStatus): A dictionary containing the ids of the CheckInstances and the new status.
    
    Returns:
        ErrorStatus: An error message and status code if the status is not found, or Success and 200 otherwise.
    """
    dbclient = DBClient.getInstance()
    if "iids" not in body:
        return "No iids", 400
    if "status" not in body:
        return "No status", 400
    iids_list = [ ObjectId(x) for x in body["iids"] ]
    dbclient.updateInDb(pentest, "checkinstances", {"_id": {"$in": iids_list}}, {"$set": {"status": body["status"], "force_status": body.get("force_status", body["status"])}}, many=True, notify=True)
    return "Success", 200

@permission("pentester")
def queueCheckInstances(pentest: str, body: BodyQueueCheckInstances) -> ErrorStatus:
    """
    Queue multiple CheckInstances for a given pentest.

    Args:
        pentest (str): The name of the pentest.
        body (BodyQueueCheckInstances): A dictionary containing the ids of the CheckInstances, the priority, and whether to force the queuing.

    Returns:
        ErrorStatus: An error message or "Success", and corresponsing status code.
    """
    if "iids" not in body:
        return "Missing iids", 400
    check_iids = set()
    force_queue = body.get("force", False)
    for check_iid in body.get("iids", []):
        check_iid = detect_objectid(check_iid)
        check_iids.add(ObjectId(check_iid))
    CheckInstance.bulk_queue(pentest, list(check_iids), body.get("priority", 0), force=force_queue)
    return "Success", 200

@permission("pentester")
def getChecksData(pentest: str, checkinstance_iid: str) -> Union[ErrorStatus,Dict[str, Any]]:
    """
    Get the getChecksData for the checkinstance.

    Args:
        pentest (str): The name of the pentest.
        checkinstance_iid (str): The id of the CheckInstance.

    Returns:
        Dict[str, Any]: A dictionary containing the checkinstance useful data.
    """
    check = CheckInstance.fetchObject(pentest, {"_id": ObjectId(checkinstance_iid)})
    if check is None:
        return "Not found", 404
    ret = {}
    result = check.getCheckInstanceInformation()
    if result is not None:
        ret[str(check.getId())] = result
    return ret

@permission("pentester")
def getManyChecksData(pentest: str, body: Dict[str, Any]) -> Union[ErrorStatus,Dict[str, Any]]:
    """
    Get the getChecksData for the checkinstance.

    Args:
        pentest (str): The name of the pentest.
        Body:
        checkinstances_iids (List[str]): The ids of the CheckInstances.

    Returns:
        Dict[str, Any]: A dictionary containing the checkinstance useful data.
    """
    if "checkinstances_iids" not in body:
        return "Missing checkinstances_iids", 400
    checkinstances_iids = body["checkinstances_iids"]
    checks = CheckInstance.fetchObjects(pentest, {"_id": {"$in": [ObjectId(x) for x in checkinstances_iids]}})
    if checks is None:
        return "Not found", 404
    ret = {}
    multi_command_line_tools: Dict[str, List[Dict[str, Any]]] = {}
    for check in checks:
        result = check.getCheckInstanceInformation()
        if result is None:
            continue
        ret[str(check.getId())] = result
        for toolId, result_tool in result["tools_not_done"].items():
            if "commandline_multi" in result_tool and result_tool["commandline_multi"] is None:
                continue
            if result_tool["commandline_multi"]["comm"] not in multi_command_line_tools:
                multi_command_line_tools[result_tool["commandline_multi"]["comm"]] = []
            multi_command_line_tools[result_tool["commandline_multi"]["comm"]].append({"tool_id": toolId, "checkinstance_id": str(check.getId()), "result_tool": result_tool})
    ret["multi_command_line_tools"] = multi_command_line_tools
    return ret
