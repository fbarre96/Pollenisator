"""Scope Model"""

from core.Models.Element import Element
from core.Models.Ip import Ip
from bson.objectid import ObjectId
from core.Models.Tool import Tool
import core.Components.Utils as Utils


class Scope(Element):
    """
    Represents a Scope object that defines a scope that will be targeted by network or domain tools.

    Attributes:
        coll_name: collection name in pollenisator database
    """

    coll_name = "scopes"

    def __init__(self, valuesFromDb=None):
        """Constructor
        Args:
            valueFromDb: a dict holding values to load into the object. A mongo fetched interval is optimal.
                        possible keys with default values are : _id (None), parent (None), tags([]), infos({}),
                        wave(""), scope(""), notes("")
        """
        if valuesFromDb is None:
            valuesFromDb = {}
        super().__init__(valuesFromDb.get("_id", None), valuesFromDb.get("parent", None), valuesFromDb.get(
            "tags", []), valuesFromDb.get("infos", {}))
        self.initialize(valuesFromDb.get("wave", ""), valuesFromDb.get("scope", ""),
                        valuesFromDb.get("notes", ""), valuesFromDb.get("infos", {}))

    def initialize(self, wave, scope="", notes="", infos=None):
        """Set values of scope
        Args:
            wave: the wave parent of this scope
            scope: a string describing the perimeter of this scope (domain, IP, NetworkIP as IP/Mask)
            notes: notes concerning this IP (opt). Default to ""
            infos: a dictionnary of additional info
        Returns:
            this object
        """
        self.wave = wave
        self.scope = scope
        self.notes = notes
        self.infos = infos if infos is not None else {}
        return self



    def __str__(self):
        """
        Get a string representation of a scope.

        Returns:
            Returns the scope string (network ipv4 range or domain).
        """
        return self.scope

    def getDbKey(self):
        """Return a dict from model to use as unique composed key.
        Returns:
            A dict (2 keys :"wave", "scope")
        """
        return {"wave": self.wave, "scope": self.scope}

    

    def isDomain(self):
        """Returns True if this scope is not a valid NetworkIP
        Returns:
            bool
        """
        return not Utils.isNetworkIp(self.scope)

    @classmethod
    def isSubDomain(cls, parentDomain, subDomainTest):
        """Returns True if this scope is a valid subdomain of the given domain
        Args:
            parentDomain: a domain that could be the parent domain of the second arg
            subDomainTest: a domain to be tested as a subdomain of first arg
        Returns:
            bool
        """
        splitted_domain = subDomainTest.split(".")
        # Assuring to check only if there is a domain before the tld (.com, .fr ... )
        topDomainExists = len(splitted_domain) > 2
        if topDomainExists:
            if ".".join(splitted_domain[1:]) == parentDomain:
                return True
        return False
