"""Defect Model."""

from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union
from bson.objectid import ObjectId
from pollenisator.core.models.element import Element
from pollenisator.server.servermodels.defect import DefectInsertResult, getTargetRepr as getTargetRepr_defect, insert as insert_defect, update as update_defect


class Defect(Element):
    """
    Represents a Defect object that defines a security defect. A security defect is a note added by a pentester on a port or ip which describes a security defect.

    Attributes:
        coll_name: collection name in pollenisator database
    """
    coll_name = "defects"

    def __init__(self, pentest: str, valuesFromDb: Optional[Dict[str, Any]] = None) -> None:
        """
        Constructor to initialize the Defect object.

        Args:
            pentest (str): An object representing a penetration test.
            valuesFromDb (Optional[Dict[str, Any]], optional): A dict holding values to load into the object. 
                A mongo fetched defect is optimal. Possible keys with default values are : _id (None), parent (None), 
                infos({}), target_id, target_type, title(""), synthesis(""), description(""), ease(""), impact(""), 
                risk(""), redactor("N/A"), type([]),  language(""), notes(""), proofs([]), fixes([]), creation_time, 
                infos, index(None). Defaults to None.
        """
        if valuesFromDb is None:
            valuesFromDb = {}
        self.proofs: List[str] = []
        super().__init__(pentest, valuesFromDb)
        if valuesFromDb is not None:
            self.initialize(valuesFromDb.get("target_id", ""), valuesFromDb.get("target_type", ""),
                            valuesFromDb.get("title", ""), valuesFromDb.get("synthesis", ""), valuesFromDb.get("description", ""),
                            valuesFromDb.get("ease", ""), valuesFromDb.get(
                                "impact", ""),
                            valuesFromDb.get(
                                "risk", ""), valuesFromDb.get("redactor", "N/A"), valuesFromDb.get("type", []),
                            valuesFromDb.get("language", ""),
                            valuesFromDb.get("notes", ""), valuesFromDb.get(
                                "proofs", []),
                            valuesFromDb.get("fixes", []), valuesFromDb.get("creation_time", None),
                            valuesFromDb.get("infos", {}),
                            valuesFromDb.get("index", 0))

    def initialize(self, target_id: str = "", target_type: str = "", title: str = "", synthesis: str = "",
                   description: str = "", ease: str = "", impact: str = "", risk: str = "", redactor: str = "N/A",
                   mtype: Optional[Union[str, List[str]]] = None, language: str = "", notes: str = "",
                   proofs: Optional[List[str]] = None, fixes: Optional[List[Dict[str, Any]]] = None,
                   creation_time: Optional[datetime] = None, infos: Optional[Dict[str, Any]] = None,
                   index: int = 0) -> 'Defect':
        """
        Set values of defect.

        Args:
            target_id (str, optional): Defect will be assigned to this target_id. Defaults to "".
            target_type (str, optional): Defect will be assigned to this target_type(target_id). Defaults to "".
            title (str, optional): A title for this defect describing what it is. Defaults to "".
            synthesis (str, optional): A short summary of what this defect is about. Defaults to "".
            description (str, optional): A more detailed explanation of this particular defect. Defaults to "".
            ease (str, optional): Ease of exploitation for this defect described as a string. Defaults to "".
            impact (str, optional): Impact the defect has on system. Described as a string. Defaults to "".
            risk (str, optional): The combination of impact/ease gives a resulting risk value. Described as a string. Defaults to "".
            redactor (str, optional): A pentester that will be the redactor for this defect. Defaults to "N/A".
            mtype (Optional[Union[str, List[str]]], optional): Types of this security defects (Application, data, etc...). Default is None.
            language (str, optional): The language in which this defect is redacted. Defaults to "".
            notes (str, optional): Notes took by pentesters. Defaults to "".
            proofs (Optional[List[str]], optional): A list of proof files, default to None.
            fixes (Optional[List[Dict[str, Any]]], optional): A list of fixes for this defect, default to empty list. Defaults to None.
            creation_time (Optional[datetime], optional): The time this defect was created. Default to None, will be auto filled if None.
            infos (Optional[Dict[str, Any]], optional): A dictionary with key values as additional information. Default to None.
            index (int, optional): The index of this defect in global defect table (only for unassigned defect). Defaults to 0.

        Returns:
            Defect: This object.
        """
        self.title = title
        self.synthesis = synthesis
        self.description = description
        self.ease = ease
        self.impact = impact
        self.risk = risk
        self.redactor = redactor
        self.mtype = mtype if mtype is not None else []
        if isinstance(self.mtype, str):
            self.mtype = [self.mtype]
        self.language = language
        self.notes = notes
        self.target_id = ObjectId(target_id)
        self.target_type = target_type
        self.infos = infos if infos is not None else {}
        self.proofs = proofs if proofs is not None else []
        self.fixes = fixes if fixes is not None else []
        self.index = index
        self.creation_time = datetime.now() if creation_time is None else creation_time
        return self

    def getData(self) -> Dict[str, Any]:
        """
        Return defect attributes as a dictionary matching Mongo stored defects.

        Returns:
            Dict[str,Any]: A dictionary with keys title, 
            synthesis, description, ease, impact, risk, redactor, type, language, notes, target_id, target_type, index, 
            proofs, creation_time, fixes, _id, infos.
        """

        return {"title": self.title, "synthesis":self.synthesis, "description":self.description, "ease": self.ease, "impact": self.impact,
                "risk": self.risk, "redactor": self.redactor, "type": self.mtype, "language":self.language, "notes": self.notes,
                "target_id": self.target_id, "target_type": self.target_type, "index":self.index,
                "proofs": self.proofs, "creation_time": self.creation_time, "fixes":self.fixes, "_id": self.getId(), "infos": self.infos}

    @classmethod
    def getSearchableTextAttribute(cls) -> List[str]:
        """
        Returns a list of attribute names that can be used for searching.

        Returns:
            List[str]: A list containing the attribute names that can be used for searching. In this case, it's ["title"].
        """
        return ["title"]

    @classmethod
    def getRisk(cls, ease: str, impact: str) -> str:
        """
        Dict to find a risk level given an ease and an impact.

        Args:
            ease (str): Ease of exploitation of this defect as a string.
            impact (str): The defect impact on system security.

        Returns:
            str: The risk level corresponding to the given ease and impact.
        """
        risk_from_ease = {"Easy": {"Minor": "Major", "Important": "Major", "Major": "Critical", "Critical": "Critical"},
                          "Moderate": {"Minor": "Important", "Important": "Important", "Major": "Major", "Critical": "Critical"},
                          "Difficult": {"Minor": "Minor", "Important": "Important", "Major": "Major", "Critical": "Major"},
                          "Arduous": {"Minor": "Minor", "Important": "Minor", "Major": "Important", "Critical": "Important"}}
        return risk_from_ease.get(ease, {}).get(impact, "N/A")

    def __str__(self) -> str:
        """
        Get a string representation of a defect.

        Returns:
            str: Returns the defect +title.
        """
        return self.title

    def getDetailedString(self) -> str:
        """
        Returns a detailed string describing for this defect.

        Returns:
            str: The defect title. If assigned, it will be prepended with ip and (udp/)port.
        """
        return self.getTargetRepr()+" "+str(self)



    def getDbKey(self) -> Dict[str, Any]:
        """
        Return a dict from model to use as unique composed key.

        Returns:
            Dict[str, Any]: A dict with keys "target_id", "target_type", "title" if pentest is not "pollenisator". 
            If pentest is "pollenisator", returns a dict with only "title" key.
        """
        if self.pentest == "pollenisator":
            return {"title": self.title}
        return {"target_id": self.target_id, "target_type": self.target_type, "title": self.title}

    def isAssigned(self) -> bool:
        """
        Returns a boolean indicating if this defect is assigned to an ip or is global.

        Returns:
            bool: True if the defect is assigned to an IP, False otherwise.
        """
        return self.target_id != ""

    def addInDb(self) -> Union[DefectInsertResult, Tuple[str, int]]:
        """
        Add this defect into database.

        Returns:
            Union[DefectInsertResult, Tuple[str, int]]: The ObjectId of the inserted document in the database, or None if the operation was not successful.
        """
        result: Union[DefectInsertResult, Tuple[str, int]] = insert_defect(self.pentest, self.getData())
        return result

    def update(self) -> Union[bool, Tuple[str, int]]:
        """
        Update this defect in the database.

        Returns:
            Union[bool, Tuple[str, int]]: True if the operation was successful, False otherwise.
        """
        result: Union[bool, Tuple[str, int]] = update_defect(self.pentest, ObjectId(self._id), self.getData())
        return result

    def getParentId(self) -> ObjectId:
        """
        Returns the parent id of this defect.

        Returns:
            ObjectId: The parent id of this defect.
        """
        return ObjectId(self.target_id)

    def getTargetRepr(self) -> str:
        """
        Returns a string representation of the target of this defect.

        Raises:
            ValueError: If the target is not found.

        Returns:
            str: A string representation of the target of this defect.
        """
        result: (Tuple[str, int] | Dict[str, str]) = getTargetRepr_defect(self.pentest, [self.target_id])
        if isinstance(result, tuple):
            raise ValueError(result[0])
        return result.get(str(self.target_id), "Target not found")