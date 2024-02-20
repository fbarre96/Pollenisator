"""Scope Model"""

from typing import Any, Dict, List, Optional, cast

from bson import ObjectId
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.models.element import Element
import pollenisator.core.components.utils as utils
from pollenisator.server.modules.cheatsheet.cheatsheet import CheckItem
from pollenisator.server.modules.cheatsheet.checkinstance import CheckInstance
from pollenisator.server.servermodels.scope import ScopeInsertResult, _updateIpsScopes, insert as scope_insert


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
            _updateIpsScopes(pentest, cast(Scope, scope))

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

    def addInDb(self) -> ScopeInsertResult:
        """
        Inserts this scope into the database.

        Returns:
            str: The id of the inserted scope.
        """
        res: ScopeInsertResult = scope_insert(self.pentest, self.getData())
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
