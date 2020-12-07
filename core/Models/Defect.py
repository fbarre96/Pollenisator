"""Defect Model."""

import os
from bson.objectid import ObjectId
from core.Models.Element import Element


class Defect(Element):
    """
    Represents a Defect object that defines a security defect. A security defect is a note added by a pentester on a port or ip which describes a security defect.

    Attributes:
        coll_name: collection name in pollenisator database
    """
    coll_name = "defects"

    def __init__(self, valuesFromDb=None):
        """Constructor
        Args:
            valueFromDb: a dict holding values to load into the object. A mongo fetched defect is optimal.
                        possible keys with default values are : _id (None), parent (None), tags([]), infos({}),
                        ip(""), port(""), proto(""), title(""), ease(""), impact(""), risk(""),
                        redactor("N/A"), type([]), notes(""), proofs([]), index(None)
        """
        if valuesFromDb is None:
            valuesFromDb = {}
        self.proofs = []
        super().__init__(valuesFromDb.get("_id", None), valuesFromDb.get("parent", None), valuesFromDb.get(
            "tags", []), valuesFromDb.get("infos", {}))
        self.initialize(valuesFromDb.get("ip", ""), valuesFromDb.get("port", ""),
                        valuesFromDb.get(
                            "proto", ""), valuesFromDb.get("title", ""),
                        valuesFromDb.get("ease", ""), valuesFromDb.get(
                            "impact", ""),
                        valuesFromDb.get(
                            "risk", ""), valuesFromDb.get("redactor", "N/A"), list(valuesFromDb.get("type", [])),
                        valuesFromDb.get("notes", ""), valuesFromDb.get("proofs", []), valuesFromDb.get("infos", {}),
                        valuesFromDb.get("index", 0))

    def initialize(self, ip, port, proto, title="", ease="", impact="", risk="", redactor="N/A", mtype=None, notes="", proofs=None, infos=None, index=0):
        """Set values of defect
        Args:
            ip: defect will be assigned to this IP, can be empty
            port: defect will be assigned to this port, can be empty but requires an IP.
            proto: protocol of the assigned port. tcp or udp.
            title: a title for this defect describing what it is
            ease: ease of exploitation for this defect described as a string 
            impact: impact the defect has on system. Described as a string 
            risk: the combination of impact/ease gives a resulting risk value. Described as a string
            redactor: A pentester that waill be the redactor for this defect.
            mtype: types of this security defects (Application, data, etc...). Default is None
            notes: notes took by pentesters
            proofs: a list of proof files, default to None.
            infos: a dictionnary with key values as additional information. Default to None
            index: the index of this defect in global defect table (only for unassigned defect)
        Returns:
            this object
        """
        self.title = title
        self.ease = ease
        self.impact = impact
        self.risk = risk
        self.redactor = redactor
        self.mtype = mtype if mtype is not None else []
        self.notes = notes
        self.ip = ip
        self.port = port
        self.proto = proto
        self.infos = infos if infos is not None else {}
        self.proofs = proofs if proofs is not None else []
        self.index = index
        return self

    @classmethod
    def getRisk(cls, ease, impact):
        """Dict to find a risk level given an ease and an impact.
        Args:
            ease: ease of exploitation of this defect as as tring
            impact: the defect impact on system security
        Returns:
            A dictionnary of dictionnary. First dict keys are eases of exploitation. Second key are impact strings.
        """
        risk_from_ease = {"Facile": {"Mineur": "Majeur", "Important": "Majeur", "Majeur": "Critique", "Critique": "Critique"},
                          "Modérée": {"Mineur": "Important", "Important": "Important", "Majeur": "Majeur", "Critique": "Critique"},
                          "Difficile": {"Mineur": "Mineur", "Important": "Important", "Majeur": "Majeur", "Critique": "Majeur"},
                          "Très difficile": {"Mineur": "Mineur", "Important": "Mineur", "Majeur": "Important", "Critique": "Important"}}
        return risk_from_ease.get(ease, {}).get(impact, "N/A")



    def __str__(self):
        """
        Get a string representation of a defect.

        Returns:
            Returns the defect +title.
        """
        return self.title

    def getDetailedString(self):
        """Returns a detailed string describing for this defect.
        Returns:
            the defect title. If assigned, it will be prepended with ip and (udp/)port
        """
        ret = ""
        if self.ip is not None:
            ret += str(self.ip)
        if self.proto is not None and self.port is not None:
            if self.proto != "tcp":
                ret += ":"+self.proto+"/"+self.port
            else:
                ret += ":"+self.port
        ret += " "+self.__str__()
        return ret

    def getDbKey(self):
        """Return a dict from model to use as unique composed key.
        Returns:
            A dict (4 keys :"ip", "port", "proto", "title")
        """
        return {"ip": self.ip, "port": self.port, "proto": self.proto, "title": self.title}

    def isAssigned(self):
        """Returns a boolean indicating if this defect is assigned to an ip or is global.
        Returns:
            bool
        """
        return self.ip != ""
