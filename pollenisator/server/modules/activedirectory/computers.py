"""
Active directory computer module, handle a computer with SMB port open.
"""
# coding: utf-8

from __future__ import absolute_import
from typing import Dict, Iterator, List, Optional, Any, Tuple, Union
from typing_extensions import TypedDict
from bson import ObjectId
from pymongo import UpdateOne
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.components.logger_config import logger
from pollenisator.core.models.element import Element
from pollenisator.server.modules.cheatsheet.cheatsheet import CheckItem
from pollenisator.server.modules.activedirectory.computer_infos import ComputerInfos
from pollenisator.server.modules.activedirectory.users import User
from pollenisator.server.modules.cheatsheet.checkinstance import CheckInstance
from pollenisator.server.permission import permission

ErrorCode = Tuple[str, int]
UsersAdminsListing = TypedDict('UsersAdminsListing', {'users': List[Dict[str, Any]], 'admins': List[Dict[str, Any]]})
ComputerInsertResult = TypedDict('ComputerInsertResult', {'res': bool, 'iid': ObjectId})

class Computer(Element):
    """
    Computer class, represents a host joined to a domain, usually with the port 445 opens

    Attributes:
        coll_name (str): the collecition name in the database
        command_variables (str): the variables inside command lines that can be replaced
    """
    coll_name = "computers"
    command_variables = ["domain"]

    def __init__(self, pentest: str, valuesFromDb: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize a Computer object. If valuesFromDb is not provided, an empty dictionary is used. The values for the 
        attributes of the Computer object are fetched from the valuesFromDb dictionary using the get method.

        Args:
            pentest (str): The name of the pentest.
            valuesFromDb (Optional[Dict[str, Union[str, List[str], Dict[str, Union[str, bool, List[str]]]]]], optional): 
            A dictionary containing the values for the attributes of the Computer object. Defaults to None.

        Attributes:
            name (str): The name of this Computer.
            ip (str): The ip of this Computer.
            domain (str): The domain of this Computer.
            admins (List[ObjectId]): The admins of this Computer.
            users (List[ObjectId]): The users of this Computer.
            infos (Dict[str, Union[str, bool, List[str]]]): The infos of this Computer.
        """
        if valuesFromDb is None:
            valuesFromDb = {}
        super().__init__(pentest, valuesFromDb)
        self.initialize(valuesFromDb.get("name"), valuesFromDb.get("ip"), \
             valuesFromDb.get("domain"),  valuesFromDb.get("admins"),  valuesFromDb.get("users"), valuesFromDb.get("infos"))

    def initialize(self, name: Optional[str] = None, 
                   ip: Optional[str] = None, domain: Optional[str] = None, admins: Optional[List[ObjectId]] = None, 
                   users: Optional[List[ObjectId]] = None, infos: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize the Computer object with the provided values. If a value is not provided, the corresponding attribute 
        is set to None. The pentest attribute is set to the current pentest if it is not provided.

        Args:
            name (Optional[str], optional): The name of the Computer object. Defaults to None.
            ip (Optional[str], optional): The ip of the Computer object. Defaults to None.
            domain (Optional[str], optional): The domain of the Computer object. Defaults to None.
            admins (Optional[List[str]], optional): The admins of the Computer object. Defaults to None.
            users (Optional[List[str]], optional): The users of the Computer object. Defaults to None.
            infos (Optional[Dict[str, Any]], optional): The infos of the Computer object. Defaults to None.

        Raises:
            ValueError: If an empty pentest name was given and the database is not set in mongo instance.
        """

        self.name = name
        self.ip = ip
        self.domain = domain
        self.admins = admins if admins is not None else []
        self.users = users if users is not None else []
        self._infos = ComputerInfos(infos)

    def __str__(self) -> str:
        """
        Get a string representation of a computer.

        Returns:
            Returns the computer domain\\name (ip).
        """
        return str(self.domain)+"\\"+str(self.name) + " ("+str(self.ip)+")"

    @classmethod
    def getSearchableTextAttribute(cls) -> List[str]:
        """
        Returns the searchable text attribute of the computer.

        Returns:
            List[str]: Returns a list of strings containing the searchable text attribute of the computer.
        """
        return ["domain", "name", "ip"]

    def getData(self) -> Dict[str, Any]:
        """
        Returns the data of the computer.

        Returns:
            Dict[str, Any]: Returns a dictionary containing the data of the computer.
        """
        return {"_id": self._id, "name":self.name, "ip":self.ip, "domain":self.domain,
            "admins":self.admins, "users": self.users, "infos":self.infos.getData()}

    @classmethod
    def fetchObjects(cls, pentest: str, pipeline: Dict[str, Any]) -> Iterator['Computer']:
        """
        Fetch many commands from database and return a Cursor to iterate over model objects.

        Args:
            pentest (str): The name of the current pentest.
            pipeline (Dict[str, Any]): A Mongo search pipeline.

        Returns:
            Iterator[Computer]: Returns a cursor to iterate on model objects.
        """
        dbclient = DBClient.getInstance()
        pipeline["type"] = "computer"
        ds = dbclient.findInDb(pentest, cls.coll_name, pipeline, True)
        if ds is None:
            return None
        for d in ds:
            yield Computer(pentest, d)

    @classmethod
    def fetchObject(cls, pentest: str, pipeline: Dict[str, Any]) -> Optional['Computer']:
        """
        Fetch a single Computer object from the database using the provided Mongo search pipeline. If no object is found, 
        None is returned.

        Args:
            pentest (str): The name of the current pentest.
            pipeline (Dict[str, Any]): A Mongo search pipeline.

        Returns:
            Optional[Computer]: The fetched Computer object or None if no object was found.
        """
        pipeline["type"] = "computer"
        dbclient = DBClient.getInstance()
        d = dbclient.findInDb(pentest, cls.coll_name, pipeline, False)
        if d is None:
            return None
        return Computer(pentest, d)

    def update(self) -> Union[bool, Tuple[str, int]]:
        """
        Update the Computer object in the database. The update method of the database is called with the current pentest, 
        the id of the Computer object, and the data of the Computer object.

        Returns:
            Union[bool, Tuple[str, int]]: The result of the update operation.
        """
        res: Union[bool, Tuple[str, int]] = update(self.pentest, self._id, self.getData())
        return res

    def addInDb(self) -> ComputerInsertResult:
        """
        Add the Computer object to the database. The insert method of the database is called with the current pentest and 
        the data of the Computer object.

        Returns:
            ComputerInsertResult: The result of the insert operation.
        """
        res: ComputerInsertResult = insert(self.pentest, self.getData())
        return res

    @classmethod
    def bulk_insert(cls, pentest: str, computers_to_add: List[Dict[str, Any]]) -> Optional[List[str]]:
        """
        Insert multiple Computer objects into the database in a single operation. If a computer already exists, it is 
        updated with the new information. If a computer is a domain controller or a SQL server, the corresponding checks 
        are added. If a computer belongs to a new domain, a check for the new domain is added.

        Args:
            pentest (str): The name of the current pentest.
            computers_to_add (List[Dict[str, Any]]): A list of dictionaries, each representing a Computer object to be 
            inserted.

        Returns:
            Optional[List[str]]: A list of the ids of the upserted Computer objects, or None if no objects were upserted.
        """
        if not computers_to_add:
            return None
        dbclient = DBClient.getInstance()
        dbclient.create_index(pentest, "computers", [("ip", 1), ("type", 1)])
        update_operations = []
        set_ip = set()
        for computer in computers_to_add:
            data = computer
            data["type"] = "computer"
            if "_id" in data:
                del data["_id"]
            updater: Dict[str, Dict[str, Any]] = {"$set":{}}
            for s in list(data.keys()):
                if s.startswith("infos."):
                    updater["$set"][s] = data[s]
                    del data[s]
            if len(updater["$set"]) == 0:
                del updater["$set"]
            updater["$setOnInsert"] = data
            if data["ip"].strip() not in set_ip:
                update_operations.append(UpdateOne({"ip": data["ip"].strip(), "type": "computer"}, updater, upsert=True))
                set_ip.add(data["ip"].strip())
            else:
                if "$setOnInsert" in updater:
                    del updater["$setOnInsert"]
                if updater:
                    update_operations.append(UpdateOne({"ip": data["ip"].strip(), "type": "computer"}, updater, upsert=True))
        if not update_operations:
            return None
        result = dbclient.bulk_write(pentest, "computers", list(update_operations))
        upserted_ids = result.upserted_ids
        if upserted_ids is None:
            return None
        if not upserted_ids and result.modified_count == 0:
            return None
        computers_inserted = Computer.fetchObjects(pentest, {"type":"computer", "ip":{"$in":list(set_ip)}})
        for computer_o in computers_inserted:
            if computer_o.infos.is_dc:
                computer_o.add_dc_checks()
                computer_o.add_domain_checks()
            if computer_o.infos.is_sqlserver:
                computer_o.add_sqlserver_checks()
            domain = computer_o.domain
            if domain is not None:
                domain = domain.lower()
            if domain is not None and domain != "":
                existingDomain = dbclient.findInDb(pentest, 
                    "computers", {"type":"computer", "domain":domain.lower()}, False)
                if existingDomain is None:
                    computer_o.addCheck("AD:onNewDomainDiscovered", {"domain":domain.lower()})
        return list(upserted_ids.values())

    @classmethod
    def getTriggers(cls) -> List[str]:
        """
        Return the list of trigger declared here

        Returns:
            List[str]: The list of triggers.
        """
        return ["AD:onFirstUserOnDC", "AD:onFirstAdminOnDC",  "AD:onNewUserOnDC", "AD:onNewAdminOnDC", 
                            "AD:onFirstUserOnComputer", "AD:onFirstAdminOnComputer", "AD:onNewUserOnComputer", "AD:onNewAdminOnComputer",
                            "AD:onNewDomainDiscovered", "AD:onNewDC", "AD:onNewSQLServer","AD:onFirstUserOnSQLServer", "AD:onFirstAdminOnSQLServer"]


    @property
    def infos(self) -> 'ComputerInfos':
        """
        Gets the infos of this Computer.

        Returns:
            ComputerInfos: The infos of this Computer.
        """
        return self._infos

    @infos.setter
    def infos(self, infos: 'ComputerInfos'):
        """Sets the infos of this Computer.

        :param infos: The infos of this Computer.
        :type infos: ComputerInfos
        """
        old_infos = self.infos
        self._infos = infos
        if self.infos.is_dc and not old_infos.is_dc:
            self.add_dc_checks()

    def checkAllTriggers(self) -> None:
        """
        Check all triggers for this Computer object. This includes checking for domain controllers, SQL servers, users, 
        admins, and domains. If a trigger is found, the corresponding check is added.
        """
        self.add_dc_checks()
        self.add_sqlserver_checks()
        self.add_user_checks()
        self.add_admin_checks()
        self.add_domain_checks()

    def add_domain_checks(self) -> None:
        """
        Add domain related checks
        """
        if self.infos.is_dc:
            self.addCheck("AD:onNewDC", { "domain":self.domain})

    def add_dc_checks(self) -> None:
        """
        Add domain controller related checks
        """
        if len(self.users) > 0:
            self.addCheck("AD:onFirstUserOnDC", {"user":self.users[0]})
        if len(self.admins) > 0:
            self.addCheck("AD:onFirstAdminOnDC", {"user":self.admins[0]})

    def add_sqlserver_checks(self) -> None:
        """
        Add sql server related checks
        """
        if self.infos.is_sqlserver:
            self.addCheck("AD:onNewSQLServer", { "domain":self.domain})
            if len(self.users) > 0:
                self.addCheck("AD:onFirstUserOnSQLServer", {"user":self.users[0]})
            if len(self.admins) > 0:
                self.addCheck("AD:onFirstAdminOnSQLServer", {"user":self.admins[0]})

    def add_user_checks(self) -> None:
        """
        Add users related checks
        """
        if len(self.users) == 1:
            if self.infos.is_dc:
                self.addCheck("AD:onFirstUserOnDC", {"user":self.users[-1]})
                self.addCheck("AD:onNewUserOnDC", {"user":self.users[-1]})
            if self.infos.is_sqlserver:
                self.addCheck("AD:onFirstUserOnSQLServer", {"user":self.users[-1]})
            self.addCheck("AD:onFirstUserOnComputer", {"user":self.users[-1]})
        if len(self.users) >= 1:
            find_user = None
            for user in self.users:
                user_o = User.fetchObject(self.pentest, {"_id":ObjectId(user)})
                if user_o is not None:
                    if user_o.username != "" and user_o.password != "":
                        find_user = user_o.getId()
                        break
            if find_user is None:
                find_user = self.users[-1]
            self.addCheck("AD:onNewUserOnComputer", {"user":find_user})

    def add_admin_checks(self) -> None:
        """
        Add admin related checks
        """
        if len(self.admins) == 1:
            if self.infos.is_dc:
                self.addCheck("AD:onFirstAdminOnDC", {"user":self.admins[-1]})
                self.addCheck("AD:onNewAdminOnDC", {"user":self.admins[-1]})
            if self.infos.is_sqlserver:
                self.addCheck("AD:onFirstAdminOnSQLServer", {"user":self.admins[-1]})
            self.addCheck("AD:onFirstAdminOnComputer", {"user":self.admins[-1]})
        if len(self.admins) >= 1:
            self.addCheck("AD:onNewAdminOnComputer", {"user":self.admins[-1]})

    def add_user(self, domain: str, username: str, password: str, infos: Optional[Dict[str, Any]] = None) -> ObjectId:
        """
        Add a user to this Computer object. If the user already exists, it is updated with the new information. If the 
        user does not exist, it is added to the database. If the user has a non-empty password, it is added to the list of 
        users of this Computer object and the user checks are added.

        Args:
            domain (str): The domain of the user.
            username (str): The username of the user.
            password (str): The password of the user.
            infos (Optional[Dict[str, Any]], optional): Additional information about the user. Defaults to None.

        Returns:
            ObjectId: The id of the added or updated user.
        """
        if infos is None:
            infos = {}
        user_m = User(self.pentest).initialize(domain, username, password, infos=infos)
        res = user_m.addInDb()
        if not res["res"]:
            user_m_db = User.fetchObject(self.pentest, {"_id":ObjectId(res["iid"])})
            if user_m_db is not None:
                user_m_db.updateInfos(infos)
        if str(res["iid"]) not in self.users and password.strip() != "":
            self.users.append(ObjectId(res["iid"]))
            self.add_user_checks()
        self.update()
        return ObjectId(res["iid"])

    def add_admin(self, domain: str, username: str, password: str) -> None:
        """
        Add an admin to this Computer object. If the admin already exists, it is updated with the new information. If the 
        admin does not exist, it is added to the database. If the admin has a non-empty password, it is added to the list of 
        admins of this Computer object and the admin checks are added.

        Args:
            domain (str): The domain of the admin.
            username (str): The username of the admin.
            password (str): The password of the admin.
        """
        res_iid = self.add_user(domain, username, password)
        if res_iid not in self.admins:
            self.admins.append(res_iid)
            self.add_admin_checks()
        self.update()

    
    @classmethod
    def replaceCommandVariables(cls, _pentest: str, command: str, data: Dict[str, Any]) -> str:
        """
        Replace the variables in the command with the corresponding values from the data dictionary. Currently, only the 
        domain variable is supported. If the domain variable is not in the data dictionary or its value is None, it is 
        replaced with an empty string.

        Args:
            pentest (str): The name of the current pentest.
            command (str): The command in which to replace the variables.
            data (Dict[str, Any]): The dictionary containing the values for the variables.

        Returns:
            str: The command with the variables replaced with their corresponding values.
        """
        command = command.replace("|domain|", "" if data.get("domain", "") is None else data.get("domain", ""))
        return command

    def addCheck(self, lvl: str, info: Dict[str, Any]) -> None:
        """
        Add a check to this Computer object. The check is fetched from the database using the provided level. If the level 
        is "AD:onNewDomainDiscovered", "AD:onNewDC", or "AD:onNewSQLServer", the domain is fetched from the info dictionary. 
        Otherwise, the user is fetched from the database using the user id from the info dictionary, and the username, 
        password, and domain are fetched from the user object. If the user is not found, an error is logged and the function 
        returns. For each fetched check, a CheckInstance is created from the CheckItem.

        Args:
            lvl (str): The level of the check to be added.
            info (Dict[str, Any]): The dictionary containing the information for the check.
        """
        checks = CheckItem.fetchObjects("pollenisator", {"lvl":lvl})
        if lvl in ["AD:onNewDomainDiscovered", "AD:onNewDC", "AD:onNewSQLServer"]:
            infos = {"domain":info.get("domain")}
        else:
            user_o = User.fetchObject(self.pentest, {"_id":ObjectId(info.get("user"))})
            if user_o is None:
                logger.error("User was not found when trying to add ActiveDirectory tool ")
                return
            username = user_o.username if user_o.username is not None else ""
            password = user_o.password if user_o.password is not None else ""
            domain = user_o.domain if user_o.domain is not None else ""
            infos = {"username":username, "password":password, "domain":domain}
        for check in checks:
            CheckInstance.createFromCheckItem(self.pentest, check, ObjectId(self._id), "computer", infos=infos)

@permission("pentester")
def delete(pentest: str, computer_iid: ObjectId) -> int:
    """
    Delete an Active Directory Computer.

    Args:
        pentest (str): The name of the current pentest.
        computer_iid (ObjectId): The id of the Computer object to be deleted.

    Returns:
        int: The result of the delete operation.
    """
    dbclient = DBClient.getInstance()
    share_dic = dbclient.findInDb(pentest, "computers", {"_id":ObjectId(computer_iid), "type":"computer"}, False)
    if share_dic is None:
        return 0
    res = dbclient.deleteFromDb(pentest, "computers", {"_id": ObjectId(computer_iid), "type":"computer"}, False)
    if res is None:
        return 0
    else:
        return res

@permission("pentester")
def update(pentest: str, computer_iid: ObjectId, body: Dict[str, Any]) -> Union[Tuple[str, int], bool]:
    """
    Update an Active Directory computer.

    Args:
        pentest (str): The name of the current pentest.
        computer_iid (ObjectId): The id of the Computer object to be updated.
        body (Dict[str, Any]): The new data for the Computer object.

    Returns:
         Union[Tuple[str, int], bool]: The result of the update operation.
    """
    computer = Computer(pentest, body) 
    dbclient = DBClient.getInstance()
    existing = Computer.fetchObject(pentest, {"_id": ObjectId(computer_iid)})
    if existing is None:
        return "not found", 404
    if computer.ip != existing.ip:
        return "Forbidden", 403
    if "type" in body:
        del body["type"]
    if "_id" in body:
        del body["_id"]
    domain = body.get("domain", None)
    if domain is not None:
        domain = domain.lower()
        body["domain"] = domain
    if domain is None or domain == "":
        return "Invalid domain", 400
    if domain is not None and domain != "":
        existingDomain = dbclient.findInDb(pentest,
             "computers", {"type":"computer", "domain":domain}, False)
        if existingDomain is None:
            computer.addCheck("AD:onNewDomainDiscovered", {"domain":domain})
    if existing.infos.is_dc != computer.infos.is_dc:
        existing.add_dc_checks()
        existing.add_domain_checks()
    if existing.infos.is_sqlserver != computer.infos.is_sqlserver:
        existing.add_sqlserver_checks()

    dbclient.updateInDb(pentest, "computers", {"_id": ObjectId(computer_iid), "type":"computer"}, {"$set": body}, False, True)
    return True

@permission("pentester")
def insert(pentest: str, body: Dict[str, Any]) -> ComputerInsertResult:
    """
    Insert a new Active Directory computer into the database. If the computer already exists, it is updated with the 
    new information. If the computer is a domain controller or a SQL server, the corresponding checks are added. If the 
    computer belongs to a new domain, a check for the new domain is added.

    Args:
        pentest (str): The name of the current pentest.
        body Dict[str, Any]: The data for the new Computer object.

    Returns:
        ComputerInsertResult: The result of the insert operation.
    """
    computer = Computer(pentest, body)
    dbclient = DBClient.getInstance()
    existing = dbclient.findInDb(pentest,
        "computers", {"type":"computer", "ip":computer.ip}, False)
    if existing is not None:
        if body.get("infos", {}).get("is_dc", False) is True:
            existing["infos"]["is_dc"] = True
            dbclient.updateInDb(pentest, "computers", {"_id": existing["_id"]}, {"$set": {"infos": existing["infos"]}}, False, True)
            computer.add_dc_checks()
            computer.add_domain_checks()
        if body.get("infos", {}).get("is_sqlserver", False) is True:
            existing["infos"]["is_sqlserver"] = True
            dbclient.updateInDb(pentest, "computers", {"_id": existing["_id"]}, {"$set": {"infos": existing["infos"]}}, False, True)
            computer.add_sqlserver_checks()
        return {"res": False, "iid": existing["_id"]}
    if "_id" in body:
        del body["_id"]
    body["type"] = "computer"

    ins_result = dbclient.insertInDb(pentest,
        "computers", body, True)
    if computer.infos.is_dc:
        computer.add_dc_checks()
        computer.add_domain_checks()
    if computer.infos.is_sqlserver:
        computer.add_sqlserver_checks()
    domain = body.get("domain", None)
    if domain is not None:
        domain = domain.lower()
        body["domain"] = domain
    if domain is not None and domain != "":
        existingDomain = dbclient.findInDb(pentest,
             "computers", {"type":"computer", "domain":domain.lower()}, False)
        if existingDomain is None:
            computer.addCheck("AD:onNewDomainDiscovered", {"domain":domain.lower()})
    iid = ins_result.inserted_id
    return {"res": True, "iid": iid}

@permission("pentester")
def getUsers(pentest: str, computer_iid: ObjectId) -> Union[ErrorCode, UsersAdminsListing]:
    """
    Get the users and admins of a Computer object. The users and admins are fetched from the database using the user 
    ids from the users and admins lists of the Computer object.

    Args:
        pentest (str): The name of the current pentest.
        computer_iid (ObjectId): The id of the Computer object.

    Returns:
        Union[Tuple[str, int], Dict[str, List[Dict[str, Any]]]]: If the Computer object is not found, a tuple containing 
        the string "Not found" and the status code 404 is returned. Otherwise, a dictionary containing the lists of users 
        and admins is returned.
    """
    dbclient = DBClient.getInstance()
    computer_m = Computer.fetchObject(pentest, {"_id":ObjectId(computer_iid)})
    if computer_m is None:
        return "Not found", 404
    users = dbclient.findInDb(pentest, "users", { "type":"user", "_id" : { "$in" : [ObjectId(x) for x in computer_m.users ]} } , multi=True)
    if users is None:
        users = []
    admins = dbclient.findInDb(pentest, "users", { "type":"user", "_id" : { "$in" : [ObjectId(x) for x in computer_m.admins ]} }, multi=True)
    if admins is None:
        admins = []
    return {"users":list(users), "admins":list(admins)}
