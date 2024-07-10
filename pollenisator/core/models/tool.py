"""Tool Model. A tool is an instanciation of a command against a target"""

import os
from typing import Any, Dict, List, Optional, Set, Tuple, Union, cast
from typing_extensions import TypedDict
import bson
from pymongo import InsertOne, UpdateOne
import pymongo
from pollenisator.core.components.socketmanager import SocketManager
import pollenisator.server.modules.cheatsheet.checkinstance as checkinstance
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.models.command import Command
from pollenisator.core.models.element import Element
from bson.objectid import ObjectId
from datetime import datetime
import pollenisator.core.components.utils as utils
from pollenisator.plugins.plugin import Plugin
from pollenisator.server.modules.cheatsheet.cheatsheet import CheckItem
from pollenisator.core.components.logger_config import logger

QueueTaskSuccess = TypedDict('QueueTaskSuccess', {'tool_iid': str})
QueueTaskFail = TypedDict('QueueTaskFail', {'tool_iid': str, 'error': str})
QueueTasksResult = TypedDict('QueueTasksResult', {'successes': List[QueueTaskSuccess], 'failures': List[QueueTaskFail]})
ErrorStatus = Tuple[str, int]
ToolInsertResult = TypedDict('ToolInsertResult', {"res": bool, "iid": ObjectId})

class Tool(Element):
    """
    Represents a Tool object that defines a tool. A tool is a command run materialized on a runnable object (wave, scope, ip, or port)

    Attributes:
        coll_name: collection name in pollenisator database
        command_variables: list of command variables
    """
    coll_name = "tools"
    command_variables = ["tool.infos.*"]

    def __init__(self, pentest: str, valuesFromDb: Optional[Dict[str, Any]] = None) -> None:
        """
        Constructor for the Tool class.

        Args:
            pentest (str): The name of the pentest.
            valuesFromDb (Optional[Dict[str, Any]], optional): A dictionary holding values to load into the object. 
            A mongo fetched interval is optimal. Possible keys with default values are : _id(None), parent(None),  
            infos({}), name(""), wave(""), scope(""), ip(""), port(""), proto("tcp"), lvl(""), text(""), dated("None"),
            datef("None"), scanner_ip("None"), status([]), notes(""), resultfile(""), plugin_used(""). Defaults to None.
        """
        if valuesFromDb is None:
            valuesFromDb = {}
        super().__init__(pentest, valuesFromDb)
        self.datef = "None"
        self.dated = "None"
        self.scanner_ip = "None"
        self.resultfile = ""
        self.plugin_used = ""
        self.text = ""
        self.notes = ""
        self.status: List[str] = []
        command_iid_or_none: Optional[ObjectId] = ObjectId(valuesFromDb.get("command_iid", None)) if "command_iid" in valuesFromDb else None
        check_iid_or_none: Optional[ObjectId] = ObjectId(valuesFromDb.get("check_iid", None)) if "check_iid" in valuesFromDb else None
        self.initialize(command_iid_or_none, check_iid_or_none, valuesFromDb.get("wave", ""),
                        valuesFromDb.get("name", None),
                        valuesFromDb.get(
                            "scope", ""), valuesFromDb.get("ip", ""),
                        str(valuesFromDb.get("port", "")), valuesFromDb.get(
                            "proto", "tcp"),
                        valuesFromDb.get(
                            "lvl", ""), valuesFromDb.get("text", ""),
                        valuesFromDb.get("dated", "None"), valuesFromDb.get(
                            "datef", "None"),
                        valuesFromDb.get(
                            "scanner_ip", "None"), valuesFromDb.get("status", []), valuesFromDb.get("notes", ""), valuesFromDb.get("resultfile", ""), valuesFromDb.get("plugin_used", ""), valuesFromDb.get("infos", {}))

    def initialize(self, command_iid: Optional[ObjectId], check_iid: Optional[ObjectId] = None, wave: Optional[str] = "", name: Optional[str] = None, scope: Optional[str] = "", ip: Optional[str] = "", port: Optional[str] = "", proto: Optional[str] = "tcp", lvl: str = "", text: str = "",
                   dated: str = "None", datef: str = "None", scanner_ip: str = "None", status: Optional[Union[str, List[str]]] = None, notes: str = "", resultfile: str = "", plugin_used: str = "", infos: Optional[Dict[str, Any]] = None) -> 'Tool':
        """
        Initializes the tool with the provided values.

        Args:
            command_iid (Optional[ObjectId]): iid of the command.
            check_iid (Optional[ObjectId], optional): The checkInstance iid if associated with one. Defaults to None.
            wave (Optional, optional): The target wave name of this tool (only if lvl is "wave"). Defaults to "".
            name (Optional[str], optional): Tool name, if None it will be crafted. Defaults to None.
            scope (Optional, optional): The scope string of the target scope of this tool (only if lvl is "network"). Defaults to "".
            ip (Optional, optional): The target ip "ip" of this tool (only if lvl is "ip" or "port"). Defaults to "".
            port (Optional, optional): The target port "port number" of this tool (only if lvl is "port"). Defaults to "".
            proto (Optional, optional): The target port "proto" of this tool (only if lvl is "port"). Defaults to "tcp".
            lvl (str, optional): The tool level of exploitation (wave, network, ip or port/). Defaults to "".
            text (str, optional): The command to be launched. Can be empty if name is matching a command. Defaults to "".
            dated (str, optional): A starting date and time for this interval in format : '%d/%m/%Y %H:%M:%S'. or the string "None". Defaults to "None".
            datef (str, optional): An ending date and time for this interval in format : '%d/%m/%Y %H:%M:%S'. or the string "None". Defaults to "None".
            scanner_ip (str, optional): The worker name that performed this tool. "None" if not performed yet. Default is "None".
            status (Optional[Union[str, List[str]]], optional): A list of status string describing this tool state. Default is None. (Accepted values for string in list are done, running, OOT, OOS). Defaults to None.
            notes (str, optional): Notes concerning this tool (opt). Default to "".
            resultfile (str, optional): An output file generated by the tool. Default is "".
            plugin_used (str, optional): The plugin used when this tool was imported. Default is "".
            infos (Optional[Dict[str, Any]], optional): A dictionary of additional info. Defaults to None.

        Returns:
            Tool: This object.
        """
        if name is None:
            if command_iid is not None:
                dbclient = DBClient.getInstance()

                res = dbclient.findInDb(self.pentest, "commands", {"$or": [
                    {"original_iid":ObjectId(command_iid)},
                    {"_id": ObjectId(command_iid)}
                ]}, False)
                name = res.get("name")
                if name is None:
                    raise ValueError("Tool name is not defined and cannot be fetched from command. Please provide a name.")
                self.command_iid = ObjectId(res["_id"])
        else:
            self.command_iid = ObjectId(command_iid)
        self.check_iid: Optional[ObjectId] = ObjectId(check_iid) if check_iid is not None else None
        self.name: str = name
        self.wave = wave
        self.scope = scope
        self.ip = ip
        self.port = str(port)
        self.proto = proto
        self.lvl = lvl
        self.text = text
        self.dated = dated
        self.datef = datef
        self.scanner_ip = scanner_ip
        self.notes = notes
        self.resultfile = resultfile
        self.plugin_used = plugin_used
        self.infos = infos if infos is not None else {}
        if status is None:
            status = []
        elif isinstance(status, str):
            status = [status]
        self.status = status
        self.repr_string = self.getDetailedString()
        return self

    def getData(self) -> Dict[str, Any]:
        """
        Returns a dictionary containing the data of this tool.

        Returns:
            Dict[str, Any]: A dictionary containing the data of this tool.
        """
        return {"command_iid": self.command_iid, "check_iid": self.check_iid, 
                "name": self.name, "wave": self.wave, "scope": self.scope,
                "ip": self.ip, "port": self.port, "proto": self.proto,
                "lvl": self.lvl, "text": self.text, "dated": self.dated,
                "datef": self.datef, "scanner_ip": self.scanner_ip,
                "notes": self.notes, "_id": self.getId(),  "infos": self.infos, "status":self.getStatus()}

    @classmethod
    def getSearchableTextAttribute(cls) -> List[str]:
        """
        Returns all the searchable attributes for a tool

        Returns:
            List[str]: A list containing the attribute names that can be used for searching. In this case, it's ["name", "text"].
        """
        return ["name", "text"]

    def getStatus(self) -> List[str]:
        """
        Get the tool executing status.

        Returns:
            List[str]: Returns a list of status status are :
                OOT : Out of time = This tool is in a wave which does not have any interval for now.
                OOS : Out os scope = This tool is in an IP OOS
                done : This tool is completed
                running : This tool is being run.
                ready : this tool is ready to be run"""
        return self.status


    @classmethod
    def __sanitize(cls, var_to_path: str) -> str:
        """
        Replace unwanted chars in variable given: '/', ' ' and ':' are changed to '_'

        Args:
            var_to_path (str): a string to sanitize to use a path folder

        Returns:
            str: modified arg as string

        """
        var_to_path = var_to_path.replace("/", "_")
        var_to_path = var_to_path.replace(" ", "_")
        var_to_path = var_to_path.replace(":", "_")
        return var_to_path

    def getOutputDir(self, pentest_uuid: str) -> str:
        """
        Get the tool required output directory path.

        Args:
            pentest_uuid (str): The pentest database uuid.

        Returns:
            str: The output directory of this tool instance.
        """
        # get command needed directory
        output_dir = Tool.__sanitize(
            pentest_uuid)+"/"+Tool.__sanitize(self.name)+"/"
        if self.wave != "" and self.wave is not None:
            output_dir += Tool.__sanitize(self.wave)+"/"
        if self.scope != "" and self.scope is not None:
            output_dir += Tool.__sanitize(self.scope)+"/"
        if self.ip != "" and self.ip is not None:
            output_dir += Tool.__sanitize(self.ip)+"/"
        if self.port != "" and self.port is not None:
            port_dir = str(self.port) if str(self.proto) == "tcp" else str(
                self.proto)+"/"+str(self.port)
            output_dir += Tool.__sanitize(port_dir)+"/"
        return output_dir

    def getResultFile(self) -> str:
        """
        Returns the result file of this tool.

        Returns:
            str: The result file of this tool.
        """
        return self.resultfile


    def setOutOfTime(self) -> None:
        """
        Set this tool as out of time (not matching any interval in wave).
        Add "OOT" in status if it's not already there.
        """
        if "OOT" not in self.status:
            self.status.append("OOT")
            self.updateInDb( {"status": self.status})

    def setOutOfScope(self, pentest: str) -> None:
        """
        Set this tool as out of scope (is not matching any scope in wave).
        Add "OOS" in status if it's not already there.

        Args:
            pentest (str): The name of the pentest.
        """
        if not "OOS" in self.status:
            self.status.append("OOS")
            self.updateInDb( {"status": self.status})

    def addInDb(self, base: Optional[Dict[str, Any]] = None, update_check: bool = False) -> ToolInsertResult:
        """
        Inserts a tool into the database.

        Args:
            base (Optional[Dict[str, Any]]): A dictionary containing the base data for the tool. If provided, this data is used to check for an existing tool in the database.
            update_check (bool): Whether to update the check associated with the tool.

        Returns:
            ToolInsertResult: A string indicating an error or a dictionary containing the result of the operation and the id of the inserted tool.
        """
        dbclient = DBClient.getInstance()
        body = self.getData()
        # Checking unicity
        db_base = self.getDbKey()
        if base is not None:
            for k,v in base.items():
                if k is not None and v is not None:
                    db_base[str(k)] = v
        existing = dbclient.findInDb(self.pentest, "tools", db_base, False)
        if existing is not None:
            return {"res":False, "iid":existing["_id"]}
        if "_id" in body:
            del body["_id"]
        # Checking port /service tool
        parent = self.getParentId()
        # Inserting tool
        db_base["name"] = body.get("name", "")
        db_base["ip"] = body.get("ip", "")
        db_base["scope"] = body.get("scope", "")
        db_base["port"] = body.get("port", "")
        db_base["proto"] = body.get("proto", "")
        db_base["command_iid"] = body.get("command_iid", "")
        db_base["check_iid"] = body.get("check_iid", "")
        db_base["scanner_ip"] = body.get("scanner_ip", "None")
        db_base["dated"] = body.get("dated", "None")
        db_base["datef"] = body.get("datef", "None")
        db_base["text"] = body.get("text", "")
        db_base["status"] = body.get("status", [])
        db_base["notes"] = body.get("notes", "")
        db_base["infos"] = body.get("infos", {})
        res_insert = dbclient.insertInDb(self.pentest, "tools", db_base, parent)
        ret = res_insert.inserted_id
        self._id = ret
        if db_base["check_iid"] != "" and update_check:
            try:
                check = checkinstance.CheckInstance.fetchObject(self.pentest, {"_id":ObjectId(db_base["check_iid"])})
            except bson.errors.InvalidId:
                return {"res":True, "iid":ret}
            if check is not None:
                check.updateInfosCheck()
        # adding the appropriate tools for this scope.
        return {"res":True, "iid":ret}

    def updateInDb(self, data: Optional[Dict[str, Any]] = None) -> bool:
        """
        Update the tool in the database with the provided data.
        
        Args:
            data (Optional[Dict[str, Any]]): The data to update the tool with.
            
        Returns:
            bool: True if the update was successful, False otherwise.
        """
        dbclient = DBClient.getInstance()
        new_data = self.getData()
        data = {} if data is None else data
        new_data |= data
        if "_id" in new_data:
            del new_data["_id"]
        dbclient.updateInDb(self.pentest, "tools", {"_id":ObjectId(self.getId())}, {"$set":new_data})
        if self.check_iid is not None:
            check_o = checkinstance.CheckInstance.fetchObject(self.pentest, {"_id":ObjectId(self.check_iid)})
            if check_o is not None:
                check_o.updateInfosCheck()
        return True

    def deleteFromDb(self) -> int:
        """
        Delete the tool from the database.

        Returns:
            int: The number of deleted tools.
        """
        dbclient = DBClient.getInstance()
        res = dbclient.deleteFromDb(self.pentest, "tools", {"_id": ObjectId(self.getId())}, False)
        if self.check_iid is not None:
            check_m = checkinstance.CheckInstance.fetchObject(self.pentest, {"_id":ObjectId(self.check_iid)})
            if check_m is not None:
                check_m.updateInfosCheck()
        if res is None:
            return 0
        else:
            return res

    def getCommand(self) -> Dict[str, Any]:
        """
        Get the tool associated command.

        Returns:
            Dict[str, Any]: The Mongo dict command fetched instance associated with this tool's name.
        """
        dbclient = DBClient.getInstance()
        commandTemplate = dbclient.findInDb(self.pentest,
                                                 "commands", {"_id": ObjectId(self.command_iid)}, False)
        return commandTemplate

    def getCheckItem(self) -> Optional['CheckItem']:
        """
        Get the CheckItem associated with this tool.

        Returns:
            Optional[CheckItem]: The CheckItem instance associated with this tool's check iid, or None if no such CheckItem exists.
        """
        try:
            ObjectId(self.check_iid)
        except bson.errors.InvalidId:
            return None
        check: Optional[checkinstance.CheckInstance] = checkinstance.CheckInstance.fetchObject(self.pentest, {"_id":ObjectId(self.check_iid)})
        if check is None:
            return None
        return check.getCheckItem()

    def setInScope(self) -> None:
        """
        Set this tool as in scope (matching any scope in wave).
        Remove "OOS" from status if it's there.
        """
        if "OOS" in self.status:
            self.status.remove("OOS")
            self.updateInDb( {"status": self.status})

    def setInTime(self) -> None:
        """
        Set this tool as in time (matching any interval in wave).
        Remove "OOT" from status if it's there.
        """
        if "OOT" in self.status:
            self.status.remove("OOT")
            self.updateInDb({"status":self.status})

    def delete(self) -> int:
        """
        ALIAS OF deleteFromDb :
        Delete the tool represented by this model in the database.

        Returns:
            int: The number of deleted tools.
        """
        return self.deleteFromDb()

    def getParentId(self) -> Optional[ObjectId]:
        """
        Get the parent id of this tool.

        Returns:
            Optional[ObjectId]: The parent id if it exists, None otherwise.
        """
        try:
            if self.check_iid is not None:
                return self.check_iid
            else:
                return None
        except TypeError:
            # None type returned:
            return None

    def findQueueIndexFromPrio(self, queue: List[Dict[str, Any]]) -> int:
        """
        Find the index in the queue where the tool should be inserted based on its priority.

        Args:
            queue (List[Dict[str, Any]]): The queue of tools.

        Returns:
            int: The index where the tool should be inserted in the queue.
        """
        check_item = self.getCheckItem()
        if check_item is None:
            return 0
        priority = check_item.priority
        i=0
        for tool_info in queue:
            queue_priority = tool_info.get("priority", 0)
            if queue_priority > priority:
                return i
            i+=1
        return i

    def addToQueue(self, index: Optional[int] = None) -> Tuple[bool, str]:
        """
        Add this tool to the queue.

        Args:
            index (Optional[int], optional): The index at which to insert the tool in the queue. If None, the tool is inserted based on its priority. Defaults to None.

        Returns:
            Tuple[bool, str]: A tuple containing a boolean indicating the success of the operation and a message.
        """
        dbclient = DBClient.getInstance()
        queue_db = dbclient.findInDb(self.pentest, "autoscan", {"type":"queue"}, False) 
        if queue_db is None:
            queue = list()
            dbclient.insertInDb(self.pentest, "autoscan", {"type":"queue", "tools":[]}) 
        else:
            queue = list(queue_db["tools"])
        if self.getId() in queue:
            return False, "Already in queue"
        check_item = self.getCheckItem()
        if check_item is None:
            priority = 0
        else:
            priority = check_item.priority
        if index is None:
            index=self.findQueueIndexFromPrio(queue)
            queue.insert(index, {"iid":self.getId(), "priority":priority})
        else:
            try:
                queue.insert(index, {"iid":self.getId(), "priority":priority})
            except IndexError:
                return False, "Index error"
        dbclient.updateInDb(self.pentest, "autoscan", {"type":"queue"}, {"$set":{"tools":queue}})
        return True, "Added to queue"

    def removeFromQueue(self) -> Tuple[bool, str]:
        """
        Remove this tool from the queue.

        Returns:
            Tuple[bool, str]: A tuple containing a boolean indicating the success of the operation and a message.
        """
        dbclient = DBClient.getInstance()
        dbclient.updateInDb(self.pentest, "autoscan", {"type":"queue"}, {"$pull":{"tools":{"iid":self.getId()}}})
        return True, "remove from to queue"

    @staticmethod
    def clearQueue(pentest: str) -> Tuple[bool, str]:
        """
        Clear the queue of tools.

        Args:
            pentest (str): The name of the pentest.

        Returns:
            Tuple[bool, str]: A tuple containing a boolean indicating the success of the operation and a message.
        """
        dbclient = DBClient.getInstance()
        dbclient.updateInDb(pentest, "autoscan", {"type":"queue"}, {"$set":{"tools":[]}})
        return True, "Cleared queue"

    def getCommandLine(self, commandline_options: str = "") -> Union[ErrorStatus, Dict[str,str]]:
        if commandline_options != "":
            self.text = commandline_options
            self.updateInDb({"text":commandline_options})
        # GET COMMAND OBJECT FOR THE TOOL
        command_o: Union[str, Command]
        if self.text == "":
            try:
                command_o = Command(self.pentest, self.getCommand())
                if command_o is None:
                    return "Associated command was not found", 404
            except:
                return "No command was not found", 404
        else:
            command_o = str(self.text)
        # Replace vars in command text (command line)
        comm = self.getCommandToExecute(command_o)
        # Read file to execute for given tool and prepend to final command
        if comm == "":
            return "An empty command line was crafted", 400
        # Load the plugin
        ext = ""
        mod = self.getPlugin()
        if mod is None:
            return "Plugin not found for this tool", 400
        # craft outputfile name
        comm_complete = mod.changeCommand(comm, "|outputDir|", mod.getFileOutputExt())
        ext = mod.getFileOutputExt()
        return {"comm":comm, "ext":ext, "comm_with_output":comm_complete}

    def getCommandToExecute(self, command_o: Union[str, Command]) -> str:
        """
        Get the tool bash command to execute.
        Replace the command's text's variables with tool's informations.

        Args:
            command_o (Union[str, Command]): The command or command string to execute.

        Returns:
            str: The bash command of this tool instance, a marker |outputDir| is still to be replaced.
        """
        toolHasCommand = self.text
        if isinstance(command_o, str):
            command = command_o
            self.text = command
        else:
            if toolHasCommand is not None and toolHasCommand.strip() != "":
                command = self.text
            else:
                command = command_o.text
        data = self.getData()
        if self.check_iid is not None:
            check = checkinstance.CheckInstance.fetchObject(self.pentest, {"_id":ObjectId(self.check_iid)})
            if check is not None:
                target = check.getTargetData()
                if target is not None:
                    infos = {**data.get("infos", {}), **target.get("infos", {})}
                    data |= target
                    data["infos"] = infos
        command = Element.replaceAllCommandVariables(self.pentest, command, data)
        if isinstance(command_o, str):
            return command
        return command

    @classmethod
    def replaceCommandVariables(cls, _pentest: str, command: str, data: Dict[str, Any]) -> str:
        """
        Replace the variables in the command with the corresponding information from the data.

        Args:
            pentest (str): The name of the pentest.
            command (str): The command to be modified.
            data (Dict[str, Any]): The data containing the information to replace the variables in the command.

        Returns:
            str: The command with the variables replaced by the corresponding information from the data.
        """
        command = cls.unpack_info(data.get("infos",{}), command, depth=0, max_depth=3)
        return command

    @classmethod
    def unpack_info(cls, infos_dict: Dict[str, Any], command: str, depth: int = 0, max_depth: int = 3) -> str:
        """
        Recursively unpack infos dict into command string.

        Args:
            infos_dict (dict): The dictionary containing the information to be unpacked.
            command (str): The command string to be modified.
            depth (int, optional): The current depth of the recursion. Defaults to 0.
            max_depth (int, optional): The maximum depth of the recursion. Defaults to 3.

        Returns:
            str: The command string with the information from the dictionary unpacked into it.
        """
        if depth > max_depth:
            return ""
        for key in infos_dict.keys():
            if isinstance(infos_dict[key], dict):
                command = cls.unpack_info(infos_dict[key], command, depth+1, max_depth)
            else:
                command = command.replace("|tool.infos."+str(key)+"|", str(infos_dict.get(key, '')))
        return command

    def getPluginName(self) -> Optional[str]:
        """
        Get the name of the plugin used by this tool.

        Returns:
            Optional[str]: The name of the plugin if it exists, None otherwise.
        """
        dbclient = DBClient.getInstance()
        if self.plugin_used != "":
            return self.plugin_used
        command_o = dbclient.findInDb(self.pentest,"commands",{"_id": ObjectId(self.command_iid)}, False)
        if command_o and "plugin" in command_o.keys():
            return str(command_o["plugin"])
        return None

    def getPlugin(self) -> Optional[Plugin]:
        """
        Get the plugin module used by this tool.

        Returns:
            Optional[Plugin]: The plugin module if it exists, None otherwise.
        """
        mod_name = self.getPluginName()
        if mod_name:
            mod = utils.loadPlugin(mod_name)
            return mod
        return None

    def markAsDone(self, file_name: Optional[str] = None) -> None:
        """
        Set this tool status as done but keeps OOT or OOS.

        Args:
            file_name (Optional[str], optional): The resulting file of this tool execution. Default is None.
        """
        self.datef = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
        newStatus = ["done"]
        if "OOS" in self.status:
            newStatus.append("OOS")
        if "OOT" in self.status:
            newStatus.append("OOT")
        self.status = newStatus
        self.resultfile = file_name if file_name is not None else ""
        dbclient = DBClient.getInstance()
        dbclient.updateInDb("pollenisator", "workers", {"name":self.scanner_ip}, {"$pull":{"running_tools": {"pentest":self.pentest, "iid":self.getId()}}})

    def markAsError(self, msg: str = "") -> None:
        """
        Set this tool status as not done by removing "done" or "running" and adding an error status.
        Also resets starting and ending date as well as worker name.

        Args:
            msg (str, optional): The error message. Defaults to "".
        """
        self.dated = "None"
        self.datef = "None"
        dbclient = DBClient.getInstance()
        dbclient.updateInDb("pollenisator", "workers", {"name":self.scanner_ip}, {"$pull":{"running_tools": {"pentest":self.pentest, "iid":self.getId()}}})
        self.scanner_ip = "None"
        if "done" in self.status:
            self.status.remove("done")
        if "running" in self.status:
            self.status.remove("running")
        self.notes = msg
        self.status.append("error")

    def markAsTimedout(self) -> None:
        """
        Set this tool status as not done by removing "done" or "running" and adding a "timedout" status.
        Also resets starting and ending date as well as worker name.
        """
        self.dated = "None"
        self.datef = "None"
        dbclient = DBClient.getInstance()
        dbclient.updateInDb("pollenisator", "workers", {"name":self.scanner_ip}, {"$pull":{"running_tools": {"pentest":self.pentest, "iid":self.getId()}}})
        self.scanner_ip = "None"
        if "done" in self.status:
            self.status.remove("done")
        if "running" in self.status:
            self.status.remove("running")
        self.status.append("timedout")

    def markAsNotDone(self) -> None:
        """
        Set this tool status as not done by removing "done" or "running" status.
        Also resets starting and ending date as well as worker name.
        """
        self.dated = "None"
        self.datef = "None"
        dbclient = DBClient.getInstance()
        if self.scanner_ip != "None":
            dbclient.updateInDb("pollenisator", "workers", {"name":self.scanner_ip}, {"$pull":{"running_tools": {"pentest":self.pentest, "iid":self.getId()}}})
        self.scanner_ip = "None"
        if "done" in self.status:
            self.status.remove("done")
        if "running" in self.status:
            self.status.remove("running")


    def markAsRunning(self, workerName: str) -> None:
        """
        Set this tool status as running but keeps OOT or OOS.
        Sets the starting date to current time and ending date to "None"

        Args:
            workerName (str): The worker name that is running this tool.
        """
        self.dated = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
        self.datef = "None"
        newStatus = ["running"]
        if "OOS" in self.status:
            newStatus.append("OOS")
        if "OOT" in self.status:
            newStatus.append("OOT")
        if "timedout" in self.status:
            newStatus.append("timedout")
        self.status = newStatus
        self.scanner_ip = workerName
        dbclient = DBClient.getInstance()
        dbclient.updateInDb("pollenisator", "workers", {"name":workerName}, {"$addToSet":{"running_tools": {"pentest":self.pentest, "iid":self.getId()}}}, notify=True)



    def getDbKey(self) -> Dict[str, Any]:
        """
        Return a dictionary from the model to use as a unique composed key.

        Returns:
            Dict[str, Any]: A dictionary containing the wave, name, level, and check id of the tool.
        """
        base = {"wave": self.wave, "name":self.name, "lvl": self.lvl, "check_iid":self.check_iid}
        return base

    def getHashableDbKey(self) -> Tuple[Any, ...]:
        """
        Return a tuple from the model to use as a unique composed key.

        Returns:
            Tuple[Union[str, Any]]: A tuple containing the wave, name, level, and check id of the tool.
        """
        return tuple(list(self.getDbKey().values()))

    def __str__(self) -> str:
        """
        Get a string representation of a tool.

        Returns:
            str: The tool name. The wave name is prepended if tool lvl is "port" or "ip".
        """
        return self.name

    def getDetailedString(self) -> str:
        """
        Get a more detailed string representation of a tool.

        Returns:
            str: A detailed string representation of the tool.
        """
        if self.lvl == "import":
            return str(self.name)
        class_element = Element.getClassWithTrigger(self.lvl)
        if class_element is None:
            return str(self.name)
        return class_element.completeDetailedString(self.getData()) + str(self.name)

    def _setStatus(self, new_status: List[str], arg: Optional[str]) -> bool:
        """
        Set the status of the tool based on the new status provided.

        Args:
            new_status (List[str]): The list of new status to be set.
            arg (Any): Additional argument used in setting the status.

        Returns:
            bool: The updated tool data.
        """
        if "done" in new_status:
            if arg == "":
                arg = None
            self.markAsDone(None)
        elif "running" in new_status:
            self.markAsRunning(arg if arg is not None else "")
        elif "not_done" in new_status:
            self.markAsNotDone()
        elif "ready" in new_status:
            self.markAsNotDone()
        elif "error" in new_status:
            self.markAsError(arg if arg is not None else "")
        elif "timedout" in new_status:
            self.markAsTimedout()
        elif len(new_status) == 0:
            self.markAsNotDone()
        res: bool = self.updateInDb(self.getData())
        return res

    @classmethod
    def bulk_insert(cls, pentest: str, tools_to_add: List['Tool']) -> List[ObjectId]:
        """
        Insert multiple tools into the database in a single operation.

        Args:
            pentest (str): The name of the pentest.
            tools_to_add (List[Tool]): The list of tools to be added.

        Returns:
            List[ObjectId]: The list of ids of the upserted tools.
        """
        if not tools_to_add:
            return []
        dbclient = DBClient.getInstance()
        dbclient.create_index(pentest, "tools", [("wave", 1), ("name", 1), ("lvl", 1), ("check_iid", 1)])
        #### CHECKING UNICITY ####
        check_keys = set()
        or_conditions = []
        lkp = {}
        for tool in tools_to_add:
            hashable_key = tool.getHashableDbKey()
            lkp[hashable_key] = tool.getData()
            del lkp[hashable_key]["_id"]
            check_keys.add(hashable_key)
            or_conditions.append(tool.getDbKey())
        existing_tools = Tool.fetchObjects(pentest, {"$or": or_conditions})
        existing_checks_as_keys = set([]) if existing_tools is None else set([ existing_tool.getHashableDbKey() for existing_tool in existing_tools])
        to_add = check_keys - existing_checks_as_keys
        things_to_insert = [lkp[check] for check in to_add]
        #UPDATE EXISTING
        # Insert new
        if not things_to_insert:
            return []
        result: pymongo.results.InsertManyResult = dbclient.insertManyInDb(pentest, Tool.coll_name, things_to_insert)
        ####
        if result is None:
            return []
        inserted_ids = result.inserted_ids
        if inserted_ids is None:
            return []
        return [ObjectId(val) for val in inserted_ids]

    def update(self) -> bool:
        """
        Update the current tool in the database.

        Returns:
            bool: True if the update was successful, False otherwise.
        """
        res: bool = self.updateInDb(self.getData())
        return res

    def listResultFiles(self) -> List[str]:
        """
        List all result files for this tool.

        Returns:
            List[str]: A list of all results for this tool.
        """
        local_path = os.path.normpath(os.path.join(utils.getMainDir(), "files"))
        filepath = os.path.join(local_path, self.pentest, "result", str(self.getId()))
        filepath = os.path.normpath(filepath)
        if not filepath.startswith(local_path):
            raise ValueError("Invalid path")
        try:
            files = os.listdir(filepath)
        except FileNotFoundError as e:
            raise e
        return files

    @classmethod
    def launchTask(cls, pentest:str, tool_iid: ObjectId, socket_sid: str, worker_token: str) -> None:
        sm = SocketManager.getInstance()
        sm.socketio.emit('executeCommand', {'workerToken': worker_token, "pentest":pentest, "toolId":str(tool_iid)}, room=socket_sid)
        dbclient = DBClient.getInstance()
        dbclient.send_notify(pentest, "tools", str(tool_iid), "tool_start")
        return

    def stopTask(self, **kwargs) -> ErrorStatus:
        """
        Stop the task associated with this tool.

        Args:
            **kwargs: Additional keyword arguments.

        Returns:
           ErrorStatus: A string indicating the result of the operation or an integer indicating the status code.
        """
        logger.info("Trying to stop task %s",str(self))
        dbclient = DBClient.getInstance()
        workers = dbclient.getWorkers({})
        terminalsessionsCursor = dbclient.findInDb(self.pentest, "terminalsessions", {"target_check_iid":str(self.check_iid)+"|"+str(self._id)}, True)
        if workers is None:
            workerNames = []
        else:
            workerNames = [worker["name"] for worker in workers]
        if terminalsessionsCursor is None:
            terminalsessions = []
        else:
            terminalsessions = [session for session in terminalsessionsCursor]
        forceReset = kwargs.get("forceReset", False)
        saveScannerip = self.scanner_ip
        if forceReset:
            self.markAsNotDone()
            self.updateInDb()
        if saveScannerip == "" and len(terminalsessions) == 0:
            return "Empty worker field", 400
        if saveScannerip == "localhost":
            return "Tools running in localhost cannot be stopped through API", 405
        if saveScannerip not in workerNames and len(terminalsessions) == 0:
            return "The worker running this tool is not running anymore", 404
        socketsCursor = dbclient.findInDb("pollenisator", "sockets", {"pentest":self.pentest}, True)
        if socketsCursor is not None:
            sockets = [x for x in socketsCursor]
        if len(sockets) == 0:
            return "The worker running this tool is not running anymore", 404
        sm = SocketManager.getInstance()
        for socket in sockets:
            if socket.get("type") == "worker":
                sm.socketio.emit('stopCommand', {'pentest': self.pentest, "tool_iid":str(self.getId())}, room=socket["sid"])
            elif socket.get("type") == "terminal":
                sm.socketio.emit('stop-terminal-command', {'pentest': self.pentest, "tool_iid":str(self.getId())}, room=socket["sid"])

        if not forceReset:
            self.markAsNotDone()
            self.updateInDb()
        return "Success", 200

    def isLaunchable(self, authorized_commands: Optional[List[str]], force: bool = False) -> ErrorStatus:
        """
        Check if a tool is launchable. The tool and its command are fetched from the database. If the command is not 
        authorized for autoscan and force is not set, an error message is returned. If the tool or the command do not exist, 
        an error message is returned. The workers that support the command plugin are fetched from the database. If no worker 
        is available to launch the tool, an error message is returned. If a worker is available, the socket for the worker is 
        fetched from the database. If the socket does not exist, an error message is returned.

        Args:
            authorized_commands (Optional[List[str]]): A list of authorized commands for autoscan.
            force (bool, optional): Whether to force the launch of the tool. Defaults to False.

        Returns:
            ErrorStatus: An error message and status code if an error occurred, otherwise the socket id for 
            the worker that will launch the tool.
        """
        logger.debug("launch task : %s", str(self))

        command_o = Command.fetchObject(self.pentest, {"_id": ObjectId(self.command_iid)})
        if command_o is None:
            logger.debug("Error in launch task : command for tool not found : %s",str(self))
            return "Command associated not found", 404
        command_o = cast(Command, command_o)
        if not force:
            if authorized_commands is not None and str(command_o.getId()) not in authorized_commands:
                return "Command not authorized for autoscan", 403
        plugin_to_run = command_o.plugin
        dbclient = DBClient.getInstance()
        # Find a worker that can launch the tool without breaking limitations
        valid_workers = dbclient.findInDb("pollenisator", "workers", {"pentest": self.pentest, "supported_plugins":plugin_to_run}, True)
        logger.debug("Available workers are %s, (tool id %s)", str(valid_workers), str(self))
        choosenWorker = ""
        for worker in valid_workers:
            running_tools = dbclient.countInDb(self.pentest,"tools",{"status":"running", "scanner_ip":worker["name"]})
            if running_tools <= 5: # TODO not hardcode this parameter
                choosenWorker = worker["name"]
        if choosenWorker == "":
            logger.debug("Error in launch task : no worker available: %s", str(self))
            return "No worker available", 504
        logger.debug("Choosen worker %s for tool_iid is %s", str(self), str(choosenWorker))
        workerName = choosenWorker
        socket = dbclient.findInDb("pollenisator", "sockets", {"user":workerName}, False)
        if socket is None:
            logger.debug("Error in launching %s : socket not found to contact %s", str(self), str(workerName))
            return "Socket not found", 503
        return str(socket['sid']), 200

    @classmethod
    def queueTasks(cls, pentest: str, tools_iids: Set[ObjectId]) -> QueueTasksResult:
        """
        Queue tasks for a pentest. The tasks are fetched from the body and added to the queue. If a task is successfully added 
        to the queue, it is added to the successes list. If a task fails to be added to the queue, it is added to the failures 
        list along with the error message.

        Args:
            pentest (str): The name of the pentest.
            tools_iids (Set[ObjectId]): A list of task ids to be added to the queue.
            **kwargs (Any): Additional keyword arguments.

        Returns:
            QueueTasksResult: A dictionary containing the successes and 
            failures of adding tasks to the queue.
        """
        logger.debug("Queue tasks : %s", str(tools_iids))
        results: QueueTasksResult = {"successes":[], "failures":[]}
        tools = Tool.fetchObjects(pentest, {"_id": {"$in": list(tools_iids)}})
        if tools is None:
            return results
        for tool in tools:
            tool = cast(Tool, tool)
            tool_iid = str(tool.getId())
            res, msg = tool.addToQueue()
            if res:
                results["successes"].append({"tool_iid":str(tool_iid)})
            else:
                results["failures"].append({"tool_iid":str(tool_iid), "error":msg})
        return results

    @classmethod
    def unqueueTasks(cls, pentest: str, tools_iids: Set[ObjectId], **kwargs: Any) -> QueueTasksResult:
        """
        Remove tasks from the queue for a pentest. The tasks are fetched from the body and removed from the queue. If a task 
        is successfully removed from the queue, it is added to the successes list. If a task fails to be removed from the 
        queue, it is added to the failures list along with the error message.

        Args:
            pentest (str): The name of the pentest.
            tools_iids (Set[ObjectId]): A list of task ids to be removed from the queue.
            **kwargs (Any): Additional keyword arguments.

        Returns:
            QueueTasksResult: A dictionary containing the successes and 
            failures of removing tasks from the queue.
        """
        logger.debug("Remove tasks : %s", str(tools_iids))
        results: QueueTasksResult = {"successes":[], "failures":[]}
        for tool_iid in tools_iids:
            tool = Tool.fetchObject(pentest, {"_id": ObjectId(tool_iid)})
            if tool:
                tool = cast(Tool, tool)
                res, msg = tool.removeFromQueue()
                if res:
                    results["successes"].append({"tool_iid":str(tool_iid)})
                else:
                    results["failures"].append({"tool_iid":str(tool_iid), "error":msg})
        return results
