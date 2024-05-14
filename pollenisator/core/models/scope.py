"""Scope Model"""

from typing import Any, Dict, List, Optional, Set, cast
from typing_extensions import TypedDict

from bson import ObjectId
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.models.command import Command
from pollenisator.core.models.defect import Defect
from pollenisator.core.models.element import Element
import pollenisator.core.components.utils as utils
from pollenisator.core.models.ip import Ip
from pollenisator.server.modules.cheatsheet.cheatsheet import CheckItem
from pollenisator.server.modules.cheatsheet.checkinstance import CheckInstance

ScopeInsertResult = TypedDict('ScopeInsertResult', {'res': bool, 'iid': ObjectId})

class Scope(Element):
    """
    Represents a Scope object that defines a scope that will be targeted by network or domain tools.

    Attributes:
        coll_name: collection name in pollenisator database
        command_variables: list of command variables
    """
    command_variables = ["scope", "parent_domain"]
    coll_name = "scopes"

    def __init__(self, pentest: str, valuesFromDb: Optional[Dict[str, Any]] = None) -> None:
        """
        Constructor for the Scope class.

        Args:
            pentest (str): The name of the pentest.
            valuesFromDb (Optional[Dict[str, Any]], optional): A dictionary holding values to load into the object. 
            A mongo fetched Scope is optimal. Possible keys with default values are : _id (None), parent (None),  
            infos({}), wave(""), scope(""), notes(""). Defaults to None.
        """
        if valuesFromDb is None:
            valuesFromDb = {}
        super().__init__(pentest, valuesFromDb)
        self.initialize(valuesFromDb.get("wave", ""), valuesFromDb.get("scope", ""),
                        valuesFromDb.get("notes", ""), valuesFromDb.get("infos", {}))

    def initialize(self, wave: str, scope: str = "", notes: str = "", infos: Optional[Dict[str, Any]] = None) -> 'Scope':
        """
        Set values of scope.

        Args:
            wave (str): The wave parent of this scope.
            scope (str, optional): A string describing the perimeter of this scope (domain, IP, NetworkIP as IP/Mask). 
            Defaults to "".
            notes (str, optional): Notes concerning this IP. Defaults to "".
            infos (Optional[Dict[str, Any]], optional): A dictionary of additional info. Defaults to None.

        Returns:
            Scope: This object.
        """
        self.wave = wave
        self.scope = scope
        self.notes = notes
        self.infos = infos if infos is not None else {}
        self.repr_string = self.getDetailedString()
        return self

    def getData(self) -> Dict[str, Any]:
        """
        Returns scope attributes as a dictionary matching Mongo stored scopes.

        Returns:
            Dict[str, Any]: A dictionary with keys "wave", "scope", "notes", "_id", and "infos".
        """
        return {"wave": self.wave, "scope": self.scope, "notes": self.notes, "_id": self.getId(), "infos": self.infos}

    def __str__(self) -> str:
        """
        Get a string representation of a scope.

        Returns:
            str: Returns the scope string (network ipv4 range or domain).
        """
        return self.scope
    
    @classmethod
    def getSearchableTextAttribute(cls) -> List[str]:
        """
        Returns the list of attributes that can be used for search.

        Returns:
            List[str]: A list containing the string "scope".
        """
        return ["scope"]

    def getDbKey(self) -> Dict[str, Any]:
        """
        Returns a dictionary from model to use as unique composed key.

        Returns:
            Dict[str, str]: A dictionary with two keys: "wave" and "scope".
        """
        return {"wave": self.wave, "scope": self.scope}

    def isDomain(self) -> bool:
        """
        Checks if this scope is a domain.

        Returns:
            bool: True if this scope is not a valid NetworkIP, False otherwise.
        """
        return not utils.isNetworkIp(self.scope)

    @classmethod
    def isSubDomain(cls, parentDomain: str, subDomainTest: str) -> bool:
        """
        Returns True if this scope is a valid subdomain of the given domain.

        Args:
            parentDomain (str): A domain that could be the parent domain of the second argument.
            subDomainTest (str): A domain to be tested as a subdomain of the first argument.

        Returns:
            bool: True if the subDomainTest is a subdomain of parentDomain, False otherwise.
        """
        splitted_domain = subDomainTest.split(".")
        # Assuring to check only if there is a domain before the tld (.com, .fr ... )
        topDomainExists = len(splitted_domain) > 2
        if topDomainExists:
            if ".".join(splitted_domain[1:]) == parentDomain:
                return True
        return False

    @classmethod
    def replaceCommandVariables(cls, _pentest: str, command: str, data: Dict[str, Any]) -> str:
        """
        Replaces variables in the command with their corresponding values from the data dictionary.

        Args:
            _pentest (str): The name of the pentest.
            command (str): The command string with variables to be replaced.
            data (Dict[str, Any]): A dictionary containing the values for the variables.

        Returns:
            str: The command string with variables replaced by their corresponding values.
        """
        scope = data.get("scope", "")
        scope = "" if scope is None else scope
        command = command.replace("|scope|", scope)
        if not utils.isNetworkIp(scope):
            depths = scope.split(".")
            if len(depths) > 2:
                topdomain = ".".join(depths[1:])
            else:
                topdomain = ".".join(depths)
            command = command.replace("|parent_domain|", topdomain)
        return command

    @classmethod
    def completeDetailedString(cls, data: Dict[str, Any]) -> str:
        """
        Returns a string containing the scope from the data dictionary.

        Args:
            data (Dict[str, Any]): A dictionary containing the scope.

        Returns:
            str: The scope string from the data dictionary followed by a space.
        """
        return str(data.get("scope", ""))+" "

    @classmethod
    def updateScopesSettings(cls, pentest: str) -> None:
        """
        Updates the settings of all scopes in the given pentest.

        Args:
            pentest (str): The name of the pentest.
        """
        scopes = Scope.fetchObjects(pentest, {})
        if scopes is None:
            return
        for scope in scopes:
            scope = cast(Scope, scope)
            scope._updateIpsScopes()

    def getParentId(self) -> Optional[ObjectId]:
        """
        Returns the parent id of this scope.

        Returns:
            Optional[str]: The id of the parent wave of this scope.
        """
        dbclient = DBClient.getInstance()
        res = dbclient.findInDb(self.pentest, "waves", {"wave": self.wave}, False)
        if res is None:
            return None
        return ObjectId(res["_id"])
    
    def getCommandSuggestions(self) -> Dict[str, Any]:
        """
        Get the command suggestions for the scope.

        Returns:
            Dict[str, Any]: A dictionary containing the command suggestions.
        """
        checks = CheckInstance.fetchObjects(self.pentest, {"target_iid": ObjectId(self.getId()), "target_type": "scope"})
        if checks is None:
            return {}
        ret = {}
        for check in checks:
            check = cast(CheckInstance, check)
            result = check.getCheckInstanceInformation()
            if result is not None:
                ret[str(check.getId())] = result
        return ret

    # def get_children(self) -> Dict[str, List[Dict[str, Any]]]:
    #     """
    #     Returns the children of this scope.

    #     Returns:
    #         Dict[str, List[Dict[str, Any]]]: A list of dictionaries containing the children of this scope.
    #     """
    #     children:  Dict[str, List[Dict[str, Any]]] = {"checkinstances":[], "defects":[]}
    #     checkinstances_ids: Set[ObjectId] = set()
    #     checkitems_lkp = {}
    #     checks = CheckInstance.fetchObjects(self.pentest, {"target_iid": ObjectId(self.getId()), "target_type": "scope"})
    #     if checks is not None:
    #         for check in checks:
    #             check = cast(CheckInstance, check)
    #             children["checkinstances"].append(check.getData())
    #             if check.check_iid is not None:
    #                 checkinstances_ids.add(check.check_iid)
    #     check_items = CheckItem.fetchObjects("pollenisator", {"_id":{"$in":list(checkinstances_ids)}})
    #     commands_iids = set()
    #     if check_items is not None:
    #         for check_item in check_items:
    #             check_item = cast(CheckItem, check_item)
    #             checkitems_lkp[check_item.getId()] = check_item
    #             commands_iids.add(check_item.commands)
    #     for checkinstance in children["checkinstances"]:
    #         checkinstance["checkitem"] = checkitems_lkp[ObjectId(checkinstance["check_iid"])].getData()

    #     defects = Defect.fetchObjects(self.pentest, {"target_id": ObjectId(self.getId()), "target_type": "scope"})
    #     if defects is not None:
    #         for defect in defects:
    #             defect = cast(Defect, defect)
    #             defect_data = defect.getData()
    #             children["defects"].append(defect_data)
    #     return children

    def addInDb(self) -> ScopeInsertResult:
        """
        Inserts this scope into the database.

        Returns:
            str: The id of the inserted scope.
        """
        dbclient = DBClient.getInstance()
        base = self.getDbKey()
        existing = Scope.fetchObject(self.pentest, base)
        if existing is not None:
            existing = cast(Scope, existing)
            return {"res":False, "iid":existing.getId()}
        # Inserting scope
        parent = self.getParentId()
        data = self.getData()
        if "_id" in data:
            del data["_id"]
        res_insert = dbclient.insertInDb(self.pentest, "scopes", data, parent, notify=True)
        ret = res_insert.inserted_id
        self._id = ObjectId(ret)
        # adding the appropriate checks for this scope.
        self.add_scope_checks()
        self._updateIpsScopes()
        return {"res":True, "iid":ret}

    def _updateIpsScopes(self) -> None:
        """
        Update the scopes of all IPs in the database. If an IP fits in the given scope and the scope is not already in the IP's 
        scopes, the scope is added to the IP's scopes.
        """
        # Testing this scope against every ips
        ips = Ip.fetchObjects(self.pentest, {"in_scopes":{"$ne":self.getId()}})
        if ips is None:
            return None
        for ip_o in ips:
            ip_o = cast(Ip, ip_o)
            if ip_o.fitInScope(self.scope):
                ip_o.addScopeFitting(self.pentest, self.getId())

    def deleteFromDb(self) -> int:
        """
        Deletes this scope from the database.

        Returns:
            int: The result of the deletion operation. If the scope was not found, None is returned. Otherwise, the 
            number of deleted documents is returned.
        """
        dbclient = DBClient.getInstance()
        # deleting checks with scope
        checks = CheckInstance.fetchObjects(self.pentest, {"target_iid": ObjectId(self.getId()), "target_type": "scope"})
        if checks is not None:
            for check in checks:
                check.deleteFromDb()
        # Deleting this scope against every ips
        ips = Ip.getIpsInScope(self.pentest, ObjectId(self.getId()))
        for ip in ips:
            ip.removeScopeFitting(self.pentest, ObjectId(self.getId()))
        res = dbclient.deleteFromDb(self.pentest, "scopes", {"_id": ObjectId(self.getId())}, False)
        parent_wave = dbclient.findInDb(self.pentest, "waves", {"wave": self.wave}, False)
        if parent_wave is None:
            return 1
        dbclient.send_notify(self.pentest, "waves", parent_wave["_id"], "update", "")
        # Finally delete the selected element
        if res is None:
            return 0
        else:
            return res

    @classmethod
    def getTriggers(cls) -> List[str]:
        """
        Returns the list of triggers declared in this class.

        Returns:
            List[str]: A list of trigger names.
        """
        return ["scope:onRangeAdd", "scope:onDomainAdd", "scope:onAdd"]

    def checkAllTriggers(self) -> None:
        """
        Checks all triggers for this scope.
        """
        self.add_scope_checks()

    def add_scope_checks(self) -> None:
        """
        Adds the appropriate checks to this scope based on whether it is a network IP or a domain.
        """
        if utils.isNetworkIp(self.scope):
            self.addChecks(["scope:onRangeAdd", "scope:onAdd"])
        else:
            self.addChecks(["scope:onDomainAdd", "scope:onAdd"])

    def addChecks(self, lvls: List[str]) -> None:
        """
        Adds the appropriate checks (level check and wave's commands check) for this scope.

        Args:
            lvls (List[str]): A list of levels to be checked.
        """
        dbclient = DBClient.getInstance()
        search = {"lvl":{"$in": lvls}}
        pentest_type = dbclient.findInDb(self.pentest, "settings", {"key":"pentest_type"}, False)
        if pentest_type is not None:
            search["pentest_types"] = pentest_type["value"]
        # query mongo db commands collection for all commands having lvl == network or domain
        checkitems = CheckItem.fetchObjects("pollenisator", search)
        if checkitems is None:
            return
        for check in checkitems:
            CheckInstance.createFromCheckItem(self.pentest, check, ObjectId(self._id), "scope")
