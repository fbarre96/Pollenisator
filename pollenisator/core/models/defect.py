"""Defect Model."""

from datetime import datetime
import os
import uuid
import re
import shutil
import threading
from typing import Any, Dict, Generator, Iterator, List, Optional, Tuple, Union, cast
from typing_extensions import TypedDict
from bson.objectid import ObjectId
import pollenisator.core.components.utils as utils
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.models.element import Element

DefectInsertResult = TypedDict('DefectInsertResult', {'res': bool, 'iid': ObjectId})


sem = threading.Semaphore() 

class Defect(Element):
    """
    Represents a Defect object that defines a security defect. A security defect is a note added by a pentester on a port or ip which describes a security defect.

    Attributes:
        coll_name: collection name in pollenisator database
    """
    coll_name = "defects"
    reviewable_keys = {
        "defect": ["synthesis", "title", "impacts", "description", "ease", "impact", "risk", "cvss_score", "cvss_string"],
        "fixe" : ["synthesis", "description", "ease", "gain"]
    }

    def __init__(self, pentest: str, valuesFromDb: Optional[Dict[str, Any]] = None) -> None:
        """
        Constructor to initialize the Defect object.

        Args:
            pentest (str): An object representing a penetration test.
            valuesFromDb (Optional[Dict[str, Any]], optional): A dict holding values to load into the object. 
                A mongo fetched defect is optimal. Possible keys with default values are : _id (None), , parent (None), 
                infos({}), defect_id(None), common_translation_id(None), target_id, target_type, title(""), synthesis(""), impacts(""), description(""), ease(""), impact(""), 
                risk(""), cvss_score(0.0), cvss_string(""), redactor("N/A"), type([]),  language(""), notes(""), proofs([]), fixes([]), creation_time, 
                redacted_state("New"), editor="", infos, index(None),  perimeter([]), script(""). Defaults to None.
        """
        if valuesFromDb is None:
            valuesFromDb = {}
        super().__init__(pentest, valuesFromDb)
        self.proofs: List[str] = []
        self.creation_time: Optional[datetime] = None
        self.index = 0
        self.redacted_state = "New"
        self.mtype: Optional[Union[str, List[str]]] = []
        if valuesFromDb is not None:
            self.initialize(valuesFromDb.get("defect_id", None), valuesFromDb.get("common_translation_id",None), valuesFromDb.get("target_id", None), valuesFromDb.get("target_type", ""),
                            valuesFromDb.get("title", ""), valuesFromDb.get("synthesis", ""), valuesFromDb.get("impacts", ""), valuesFromDb.get("description", ""),
                            valuesFromDb.get("ease", ""), valuesFromDb.get(
                                "impact", ""),
                            valuesFromDb.get(
                                "risk", ""), valuesFromDb.get("cvss_score", 0.0), valuesFromDb.get("cvss_string",""), valuesFromDb.get("redactor", "N/A"), valuesFromDb.get("type", []),
                            valuesFromDb.get("language", ""),
                            valuesFromDb.get("notes", ""), valuesFromDb.get(
                                "proofs", []),
                            valuesFromDb.get("fixes", []), valuesFromDb.get("creation_time", None), valuesFromDb.get("redacted_state", "New"),
                            valuesFromDb.get("editor", ""),
                            valuesFromDb.get("infos", {}),
                            valuesFromDb.get("index", 0), valuesFromDb.get("perimeter", []), valuesFromDb.get("script", ""))

    def initialize(self, defect_id: Optional[str] = None, common_translation_id: Optional[str] = None, target_id: Optional[ObjectId] = None, target_type: str = "", title: str = "", synthesis: str = "",
                   impacts: str= "", description: str = "", ease: str = "", impact: str = "", risk: str = "", cvss_score: float = 0.0, cvss_string: str = "", redactor: str = "N/A",
                   mtype: Optional[Union[str, List[str]]] = None, language: str = "", notes: str = "",
                   proofs: Optional[List[str]] = None, fixes: Optional[List[Dict[str, Any]]] = None,
                   creation_time: Optional[datetime] = None, redacted_state: str = "New", editor="", infos: Optional[Dict[str, Any]] = None,
                   index: int = 0, perimeter: Optional[List[str]] = None, script: str = "") -> 'Defect':
        """
        Set values of defect.

        Args:
            defect_id (Optional[str], optional): A unique identifier for this defect. Defaults to None.
            common_translation_id (Optional[str], optional): The common translation id for this defect if it is a template defect. Defaults to None.
            target_id (Optional[ObjectId], optional): Defect will be assigned to this target_id. Defaults to "".
            target_type (str, optional): Defect will be assigned to this target_type(target_id). Defaults to "".
            title (str, optional): A title for this defect describing what it is. Defaults to "".
            synthesis (str, optional): A short summary of what this defect is about. Defaults to "".
            impacts (str, optional): The defect impact on system security. Defaults to "".
            description (str, optional): A more detailed explanation of this particular defect. Defaults to "".
            ease (str, optional): Ease of exploitation for this defect described as a string. Defaults to "".
            impact (str, optional): Impact the defect has on system. Described as a string. Defaults to "".
            risk (str, optional): The combination of impact/ease gives a resulting risk value. Described as a string. Defaults to "".
            cvss_score (float, optional): The CVSS score of this defect. Defaults to 0.
            cvss_string (str, optional): The CVSS string of this defect. Defaults to "".
            redactor (str, optional): A pentester that will be the redactor for this defect. Defaults to "N/A".
            mtype (Optional[Union[str, List[str]]], optional): Types of this security defects (Application, data, etc...). Default is None.
            language (str, optional): The language in which this defect is redacted. Defaults to "".
            notes (str, optional): Notes took by pentesters. Defaults to "".
            proofs (Optional[List[str]], optional): A list of proof files, default to None.
            fixes (Optional[List[Dict[str, Any]]], optional): A list of fixes for this defect, default to empty list. Defaults to None.
            creation_time (Optional[datetime], optional): The time this defect was created. Default to None, will be auto filled if None.
            redacted_state (str, optional): The redacted state of this defect. Defaults to "New".
            editor(str, optional): The editor of this defect, usually the redactor. Defaults to "".
            infos (Optional[Dict[str, Any]], optional): A dictionary with key values as additional information. Default to None.
            index (int, optional): The index of this defect in global defect table (only for unassigned defect). Defaults to 0.
            perimeter (Optional[List[str]], optional): A list of perimeters for this defect. Defaults to None.
            script (str, optional): A Python script code written by a user for this defect template. Defaults to "".
        Returns:
            Defect: This object.
        """
        if defect_id is None:
            self.defect_id = str(uuid.uuid4())
        else:
            self.defect_id = str(defect_id)
        self.common_translation_id = str(common_translation_id) if common_translation_id is not None else str(uuid.uuid4())
        self.title = title
        self.synthesis = synthesis
        self.impacts = impacts
        self.description = description
        self.ease = ease
        self.impact = impact
        self.risk = risk
        self.cvss_score = cvss_score
        self.cvss_string = cvss_string
        self.redactor = redactor
        self.mtype = mtype if mtype is not None else []
        if isinstance(self.mtype, str):
            self.mtype = [x.strip() for x in self.mtype.split(",")]
        self.language = language
        self.notes = notes
        self.target_id: Optional[ObjectId] = ObjectId(target_id) if target_id is not None else None
        self.target_type = target_type
        self.infos = infos if infos is not None else {}
        self.proofs = proofs if proofs is not None else []
        self.fixes = fixes if fixes is not None else []
        self.perimeter = perimeter if perimeter is not None else []
        if isinstance(self.perimeter, str):
            self.perimeter = [x.strip() for x in self.perimeter.split(",")]
        try:
            self.index = int(index)
        except ValueError:
            self.index = 0
        self.creation_time = datetime.now() if creation_time is None else creation_time
        self.redacted_state = "New" if redacted_state is None or redacted_state == "" else redacted_state
        self.editor = "" if editor is None else editor
        self.script = script if script is not None else ""
        self.repr_string = self.getDetailedString()

        return self

    def getData(self) -> Dict[str, Any]:
        """
        Return defect attributes as a dictionary matching Mongo stored defects.

        Returns:
            Dict[str,Any]: A dictionary with keys title, 
            defect_id, common_translation_id, synthesis, impacts, description, ease, impact, risk, cvss_score, cvss_string, redactor, type, language, notes, target_id, target_type, index, 
            proofs, creation_time, redacted_state, editor, fixes, _id, infos, script.
        """

        return {"defect_id": self.defect_id,  "common_translation_id": self.common_translation_id, "title": self.title, "synthesis":self.synthesis, "impacts":self.impacts, "description":self.description, "ease": self.ease, "impact": self.impact,
                "risk": self.risk, "cvss_score":self.cvss_score, "cvss_string":self.cvss_string, "redactor": self.redactor, "type": self.mtype, "language":self.language, "notes": self.notes,
                "target_id": self.target_id, "target_type": self.target_type, "index":int(self.index),
                "proofs": self.proofs, "creation_time": self.creation_time, "redacted_state":self.redacted_state, "editor":self.editor, "fixes":self.fixes, "perimeter":self.perimeter, "_id": self.getId(), "infos": self.infos, "script": self.script}

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
            Dict[str, Any]: A dict with keys "target_id", "target_type", "defect_id" if pentest is not "pollenisator". 
            If pentest is "pollenisator", returns a dict with only "defect_id" key.
        """
        if self.isTemplate():
            return {"defect_id": self.defect_id}
        return {"target_id": self.target_id, "target_type": self.target_type, "defect_id": self.defect_id}

    def isAssigned(self) -> bool:
        """
        Returns a boolean indicating if this defect is assigned to an ip or is global.

        Returns:
            bool: True if the defect is assigned to an IP, False otherwise.
        """
        return self.target_id is not None
    
    def isTemplate(self) -> bool:
        """
        Returns a boolean indicating if this defect is a template defect in pollenisator database.

        Returns:
            bool: True if the defect is in pollenisator database, False otherwise.
        """
        return self.pentest == "pollenisator"

    def addInDb(self) -> DefectInsertResult:
        """
        Add this defect into database.

        Raises:
            ValueError: If the target_id is not specified but the target_type is.

        Returns:
            DefectInsertResult: The ObjectId of the inserted document in the database, or None if the operation was not successful.
        """
        dbclient = DBClient.getInstance()
        try:
            self.redacted_state = "New" if self.redacted_state == "" or self.redacted_state is None else self.redacted_state
            if not self.isAssigned():
                # mostly prevent wrong index in global defect table
                sem.acquire()
            # Check existing
            base = self.getDbKey()
            existing = Defect.fetchObject(self.pentest, base)
            if existing is not None:
                sem.release()
                return {"res":False, "iid": existing.getId()}
            if self.target_id is not None and self.target_type == "":
                sem.release()
                raise ValueError("If a target_id is specified, a target_type should be specified to")
            parent = self.getParentId()
            if not self.isTemplate() and not self.isAssigned():
                # find insert position in global defect table
                self.set_defect_table_index()
            self.creation_time = datetime.now()
            if isinstance(self.mtype, str):
                self.mtype = self.mtype.split(",")
            data = self.getData()
            if "_id" in data:
                del data["_id"]
            ins_result = dbclient.insertInDb(self.pentest, "defects", data, ObjectId(parent))
            iid = ins_result.inserted_id
            self._id = iid
            if not self.isTemplate():
                self.set_proofs_from_description()
            if self.isAssigned():
                # Edit to global defect and insert it
                self.add_as_global_defect(iid)
        except Exception as e:
            raise(e)
        finally:
            if not self.isAssigned():
                sem.release()

        return {"res":True, "iid":iid}

    def add_as_global_defect(self, iid: str) -> None:
        """
        Add this defect as a global defect in the pentest database.
        """
        dbclient = DBClient.getInstance()
        global_defect = Defect(self.pentest, self.getData())
        global_defect.target_id = None
        global_defect.target_type = ""
        global_defect.parent = None
        global_defect.notes = ""
        result = global_defect.addInDb()
        if isinstance(result, tuple):
            pass
        else:
            insert_res = cast(DefectInsertResult, result)
            dbclient.updateInDb(self.pentest, "defects", {"_id":ObjectId(iid)}, {"$set":{"global_defect": insert_res["iid"]}})

    def set_proofs_from_description(self) -> None:
        """
        Set the proofs of this defect from its description.
        It searches for proof files mentioned in the description and assigns them to the defect.
        
        Returns:
            None
        """
        local_proofs = set()
        proof_groups = Defect._findProofsInDescription(self.description)
        try:
            unassigned_proofs = self.listProofFiles(getUnassigned=True)
        except FileNotFoundError:
            unassigned_proofs = []
        for proof_group in proof_groups:
            if proof_group.group(1) in unassigned_proofs:
                self.assignProof(proof_group.group(1))
                local_proofs.add(proof_group.group(1))
        self.proofs = list(local_proofs)

    def set_defect_table_index(self):
        insert_pos = Defect.findInsertPosition(self.pentest, self.risk)
        save_insert_pos = insert_pos
        defects_to_edit = []

        defect_to_edit_o = Defect.fetchObject(self.pentest, {"target_id":None, "index":int(insert_pos)})
        if defect_to_edit_o is not None:
            defects_to_edit.append(defect_to_edit_o)
        while defect_to_edit_o is not None:
            insert_pos+=1
            defect_to_edit_o = Defect.fetchObject(self.pentest, {"target_id":None,  "index":int(insert_pos)})
            if defect_to_edit_o is not None:
                defects_to_edit.append(defect_to_edit_o)
                    
        for defect_to_edit in defects_to_edit:
            defect_to_edit = cast(Defect, defect_to_edit)
            defect_to_edit.update_index(int(defect_to_edit.index)+1)
        self.index = int(save_insert_pos)

    def update_index(self, index: int) -> None:
        """
        Update the defect index in the global defect tables

        Args:
            index (int): The new index of the defect.

        Returns:
            None
        """
        dbclient = DBClient.getInstance()
        dbclient.updateInDb(self.pentest, "defects", {"_id":self.getId()}, {"$set":{"index":index}})

    def deleteFromDb(self) -> int:
        """
        Delete this defect from database
        
        Returns:
            int: the number of deleted documents
        """
        dbclient = DBClient.getInstance()
        if not self.isAssigned() and not self.isTemplate():
            # if not assigned to a pentest object it's a report defect (except in pollenisator db where it's a defect template)
            self.shift_all_index_left()
            self.delete_affiliates_defects()
        if not self.isTemplate():
            self.remove_proofs()
        res = dbclient.deleteFromDb(self.pentest, "defects", {"_id": ObjectId(self.getId())}, False)
        if res is None:
            return 0
        return res

    def remove_proofs(self) -> None:
        """
        Remove all proof files associated with this defect from the filesystem.
        """
        proofs_path = self.getProofPath()
        try:
            files = self.listProofFiles()
        except FileNotFoundError:
            files = []
        for filetodelete in files:
            filetodelete = os.path.basename(filetodelete)
            os.remove(os.path.join(proofs_path, filetodelete))
        try:
            os.rmdir(proofs_path)
        except FileNotFoundError:
            pass

    def delete_affiliates_defects(self) -> None:
        """
        Delete all defects assigned to a target that are linked to this global defect.
        """
        thisAssignedDefects = Defect.fetchObjects(self.pentest, {"global_defect": ObjectId(self.getId())})
        if thisAssignedDefects is not None:
            for thisAssignedDefect in thisAssignedDefects:
                thisAssignedDefect = cast(Defect, thisAssignedDefect)
                thisAssignedDefect.deleteFromDb()

    def shift_all_index_left(self) -> None:
        """
        Shift left the index of all global defects with index greater than this defect index.
        """
        globalDefects_iterator = Defect.fetchObjects(self.pentest, {"target_id":None})
        if globalDefects_iterator is None:
            globalDefects: List[Defect] = []
        else:
            globalDefects = cast(List[Defect], globalDefects_iterator)
        for globalDefect in globalDefects:
            globalDefect = cast(Defect, globalDefect)
            if int(globalDefect.index) > int(self.index):
                globalDefect.update_index(int(globalDefect.index)-1)

    @classmethod
    def save_template_history(cls, defect_iid: ObjectId, username: str) -> None:
        """
            Save the current version of a template defect in the database under the version collection.

            Args:
                defect_iid (ObjectId): The ObjectId of the template defect.
                username (str): The username of the user saving the history.
        """
        dbclient = DBClient.getInstance()
        data = dbclient.findInDb("pollenisator", "defects", {"_id": ObjectId(defect_iid)}, False)
        if data is None:
            raise ValueError("Defect not found")
        if "_id" in data:
            data["history_defect_iid"] = ObjectId(data["_id"])
            del data["_id"]
        data["date"] = datetime.now()
        data["editor"] = username
        dbclient.insertInDb("pollenisator", "defects_history", data)
        
    @classmethod    
    def get_template_history(cls, defect_iid: ObjectId) -> List[Dict[str, Any]]:
        """
        Get the history of a template defect.

        Args:
            defect_iid (ObjectId): The ObjectId of the template defect.

        Returns:
            List[Dict[str, Any]]: A list of dictionaries representing the history of the template defect.
        """
        dbclient = DBClient.getInstance()
        history = dbclient.findInDb("pollenisator", "defects_history", {"history_defect_iid": ObjectId(defect_iid)}, multi=True)
        if history is None:
            return []
        
        return [x for x in history]

    def save_history(self, username: str) -> None:
        """
            Save the current version in the database under the version collection.

            Args:
                username (str): The username of the user saving the history.
        """
        dbclient = DBClient.getInstance()
        if self.redacted_state == "To review" or self.redacted_state == "Reviewed":
            data = self.get_review(force=False)
            if "_id" in data:
                data["history_defect_iid"] = ObjectId(data["defect_iid"])
                data["history_review_id"] = ObjectId(data["_id"])
                del data["_id"]
        else:
            data = self.getData()
            if "_id" in data:
                data["history_defect_iid"] = ObjectId(data["_id"])
                del data["_id"]
        data["date"] = datetime.now()
        data["editor"] = username
        dbclient.insertInDb(self.pentest, "defects_history", data)

    def get_history(self) -> List[Dict[str, Any]]:
        """
        Get the history of this defect.

        Returns:
            List[Dict[str, Any]]: A list of dictionaries representing the history of this defect.
        """
        dbclient = DBClient.getInstance()
        history = dbclient.findInDb(self.pentest, "defects_history", {"history_defect_iid": ObjectId(self.getId())}, multi=True)
        if history is None:
            return []
        
        return [x for x in history]
    
    def save_review(self, data) -> None:
        """
        Save current version in the database under the version collection.

        """ 
        dbclient = DBClient.getInstance()
        new_data =  dbclient.findInDb(self.pentest, "defectsreviews", {"defect_iid": ObjectId(self.getId())}, False)
        if data is None:
            raise ValueError("No review found")
        data = {} if data is None else data
        if "_id" in data:
            del data["_id"]
        new_data |= data
        new_self = Defect(self.pentest, new_data)
        new_data = new_self.getData()
        
        new_data["defect_iid"] = self.getId()
        if "_id" in new_data:
            del new_data["_id"]
        new_data["time"] = datetime.now()
        dbclient.updateInDb(self.pentest, "defectsreviews", {"defect_iid": new_data["defect_iid"]}, {"$set":new_data}, upsert=True)

    def delete_review(self) -> None:
        """
        Delete the review of this defect from the database.

        Returns:
            None
        """
        dbclient = DBClient.getInstance()
        dbclient.deleteFromDb(self.pentest, "defectsreviews", {"defect_iid": ObjectId(self.getId())}, False)

    def get_review(self, force: bool = True) -> Dict[str, Any]:
        """
        Get the version of this defect from the database.

        Args:
            force (bool, optional): Whether to force the fetch from the database. Defaults to True.
        Returns:
            Dict[str, Any]: A dictionary representing the version of this defect.
        """
        dbclient = DBClient.getInstance()
        version = dbclient.findInDb(self.pentest, "defectsreviews", {"defect_iid": ObjectId(self.getId())}, multi=False)
        if version is not None:
            return version
        # if not found, create it if force
        if force:
            defect = dbclient.findInDb(self.pentest, "defects", {"_id":ObjectId(self.getId())}, False)
            if defect is not None:
                defect["defect_iid"] = defect["_id"]
                del defect["_id"]
                dbclient.insertInDb(self.pentest, "defectsreviews", defect)
                return defect
        return {}

    def compare_review_equal(self) -> Tuple[bool, str]:
        """
        Compare the current defect with the review version.

        Returns:
            Tuple[bool,str]: True if the current defect is different from the review version, False otherwise with a message.
        """
        current = self.getData()
        review = self.get_review()
        if review == {}:
            return True, ""
        for key in current:

            if key in Defect.reviewable_keys["defect"]:
                if key not in review:
                    return False, f"Key {key} not found in review"
                if current[key] != review[key]:
                    return False, f"Key {key} is different in review and in current"
            
        return True, ""

    def updateInDb(self, data: Optional[Dict[str, Any]] = None, clean_proofs=False) -> list[str]:
        """
        Update the current Defect object in the database.

        Args:
            data (Optional[Dict[str, Any]): The new data to set in the database.

        Returns:
            list[str]: the list of keys modified
        """
        dbclient = DBClient.getInstance()
        new_data = self.getData()
        data = {} if data is None else data
        if "_id" in data:
            del data["_id"]
        if "defect_id" in data:
            del data["defect_id"]
        if "index" in data:
            del new_data["index"] # index is not updatable directly
        new_data |= data
        new_self = Defect(self.pentest, new_data)
        if "_id" in new_data:
            del new_data["_id"]
        if "defect_id" in new_data:
            del new_data["defect_id"]
        if "index" in data:
            del new_data["index"] # index is not updatable directly
        oldRisk = self.risk
        if not new_self.isAssigned() and not self.isTemplate():
            if data.get("risk", None) is not None and not self.isTemplate():
                if new_data["risk"] != oldRisk:
                    new_data = self.update_defect_index(new_data)
        if not self.isTemplate() and "description" in data:
            new_data = self.handle_proofs_update(clean_proofs, new_data)
        dbclient.updateInDb(self.pentest, "defects", {"_id":ObjectId(self.getId())}, {"$set":new_data}, False, True)
        return list(new_data.keys())

    def handle_proofs_update(self, clean_proofs:bool, new_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle the update of proofs when the description is changed.
        Args:
            clean_proofs (bool): Whether to clean proofs that are no longer referenced in the description.
            new_data (Dict[str, Any]): The new data to set in the database.
        Returns:
            Dict[str, Any]: The updated data with the new proofs.
        """
        new_data["proofs"] = set()
        proof_groups = Defect._findProofsInDescription(new_data.get("description", ""))
        try:
            existing_proofs_to_remove = self.listProofFiles()
        except FileNotFoundError:
            existing_proofs_to_remove = []
        for proof_group in proof_groups:
            if proof_group.group(1) in existing_proofs_to_remove:
                existing_proofs_to_remove.remove(proof_group.group(1))
            if (proof_group.group(1) not in new_data["proofs"]):
                try:
                    pollenisator_images = os.listdir(os.path.join(utils.getMainDir(), "files", "pollenisator", "file","unassigned"))
                except FileNotFoundError:
                    pollenisator_images = []
                if (proof_group.group(1) in pollenisator_images):
                    continue
            new_data["proofs"].add(os.path.normpath(proof_group.group(1)))
        if clean_proofs:
            for proof_to_remove in existing_proofs_to_remove:
                self.rmProof(proof_to_remove)
        new_data["proofs"] = list(new_data["proofs"])
        return new_data

    def update_defect_index(self, new_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update the defect index in the global defect table if the risk level has changed.
        Args:
            new_data (Dict[str, Any]): The new data to set in the database.
        Returns:
            Dict[str, Any]: The updated data with the new index.
        """
        insert_pos = Defect.findInsertPosition(self.pentest, new_data["risk"])
        if int(insert_pos) > int(self.index):
            insert_pos = int(insert_pos)-1
        defectTarget = Defect.fetchObject(self.pentest, {"target_id":None, "index":insert_pos})
        if defectTarget is not None:
            Defect.moveDefect(self.pentest, self.getId(), defectTarget.getId())
        if "index" in new_data: 
            del new_data["index"]
        return new_data

    @classmethod
    def findInsertPosition(cls, pentest: str, risk: str) -> int:
        """
        Find the position to insert a new defect based on its risk level. The position is determined by the highest index of 
        defects with the same or higher risk level.

        Args:
            pentest (str): The name of the pentest.
            risk (str): The risk level of the defect.

        Returns:
            int: The position to insert the new defect.
        """
        riskLevels = ["Critical", "Major",  "Important", "Minor", "N/A"] # TODO do not hardcode those things
        riskLevelPos = riskLevels.index(risk)
        highestInd = 0
        for risklevel_i, riskLevel in enumerate(riskLevels):
            if risklevel_i > riskLevelPos:
                break
            globalDefects = Defect.fetchObjects(pentest, {"target_id":None, "risk":riskLevel})
            globalDefects = cast(Generator[Defect, None, None], globalDefects)
            for globalDefect in globalDefects:
                highestInd = max(int(globalDefect.index)+1, highestInd)
        return highestInd

    @classmethod
    def moveDefect(cls, pentest: str, defect_id_to_move: ObjectId, target_id: ObjectId) -> Union[int, Tuple[str, int]]:
        """
        Move a defect to a new position in the global defect table.

        Args:
            pentest (str): The name of the pentest.
            defect_id_to_move (ObjectId): The id of the defect to move.
            target_id (ObjectId): The id of the defect to move the defect to.

        Returns:
            Union[str, Tuple[str, int]]: The index of the defect in the global defect table if the operation was successful, 
            or a tuple containing an error message and an error code otherwise.
        """
        defect_to_move = Defect.fetchObject(pentest, {"_id":ObjectId(defect_id_to_move), "target_id":None})
        if defect_to_move is None:
            return "This global defect does not exist", 404
        defect_to_move = cast(Defect, defect_to_move)
        defect_target = Defect.fetchObject(pentest, {"_id":ObjectId(target_id), "target_id":None})
        if defect_target is None:
            return "the target global defect does not exist", 404
        defects_ordered = Defect.getGlobalDefects(pentest)
        defect_target = cast(Defect, defect_target)
        target_ind = int(defect_target.index)
        defect_to_move_ind = int(defect_to_move.index)
        del defects_ordered[defect_to_move_ind]
        defects_ordered.insert(target_ind, defect_to_move.getData())
        for defect_i in range(min(defect_to_move_ind, target_ind), len(defects_ordered)):
            defect_o = Defect(pentest, defects_ordered[defect_i])
            defect_o.update_index(defect_i)
        defect_to_move.update_index(target_ind)
        return target_ind

    def update(self, data: Dict[str, Any]) -> Union[bool, Tuple[str, int]]:
        """
        Update a defect in the database.

        Args:
            data (Dict[str, Any]): A dictionary containing the details of the defect to be updated.

        Returns:
            Union[bool, Tuple[str, int]]: True if the operation was successful, or a tuple containing an error message and 
            an error code otherwise.
        """
        if "_id" in data:
            del data["_id"] # Prevent changing the _id
        data = Defect(self.pentest, data).getData()
        if "_id" in data:
            del data["_id"] # remove _id cause it's not updatable
        dbclient = DBClient.getInstance()
        if "index" in data:
            del data["index"] # index is not updatable directly
        if not self.isAssigned() and not self.isTemplate() and data.get("risk", None) is not None:
            if data["risk"] != self.risk:
                data = self.update_defect_index(data)
        if not self.isTemplate():
            data = self.remove_proofs_from_description(data)

        dbclient.updateInDb(self.pentest, "defects", {"_id":ObjectId(self.getId())}, {"$set":data})
        return True

    def remove_proofs_from_description(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update the proofs of this defect from its description.
        It searches for proof files assigned to the defect and not mentioned in the description and removes them.
        Args:
            data (Dict[str, Any]): The new data to set in the database.
        Returns:
            None
        """
        data["proofs"] = set()
        proof_groups = Defect._findProofsInDescription(data.get("description", ""))
        try:
            existing_proofs_to_remove = self.listProofFiles()
        except FileNotFoundError:
            existing_proofs_to_remove = []
        for proof_group in proof_groups:
            if proof_group.group(1) in existing_proofs_to_remove:
                existing_proofs_to_remove.remove(proof_group.group(1))
            data["proofs"].add(proof_group.group(1))
        for proof_to_remove in existing_proofs_to_remove:
            self.rmProof(proof_to_remove)
        data["proofs"] = list(data["proofs"])
        return data

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
        class_element = Element.classFactory(self.target_type)
        if class_element is None:
            return "Target not found"
        target_elem = class_element.fetchObject(self.pentest, {"_id": ObjectId(self.target_id)})
        if target_elem is None:
            return "Target not found"
        return target_elem.getDetailedString()

    @classmethod
    def getGlobalDefects(cls, pentest: str) -> List[Dict[str, Any]]:
        """
        Get all global defects for a pentest. Global defects are defects that are not assigned to a specific target.

        Args:
            pentest (str): The name of the pentest.

        Returns:
            List[Dict[str, Any]]: A list of dictionaries, each representing a global defect. The defects are ordered by their index.
        """
        defects = Defect.fetchObjects(pentest, {"target_id": None})
        if defects is None:
            return []
        defects_ordered = []
        for defect in defects:
            defects_ordered.append(defect.getData())
        return sorted(defects_ordered, key=lambda defect: int(defect["index"]))

    @staticmethod
    def _findProofsInDescription(description: str) -> Iterator[re.Match[str]]:
        """
        Find all image references in a description. The function looks for markdown image syntax (![alt text](url)) 
        where the url does not start with "http".

        Args:
            description (str): The description to search for image references.

        Returns:
            Iterator[re.Match[str]]:: An iterator yielding match objects for each image reference found.
        """
        regex_images = r"!\[.*\]\(((?!http).*)\)" # regex to find images in markdown
        return re.finditer(regex_images, description)


    def getProofPath(self, getUnassigned: bool = False) -> str:
        """
        Get the local path for the proof of a defect.

        Args:
            getUnassigned (bool, optional): Whether to get the path for unassigned defects. Defaults to False.

        Returns:
            str: The local path for the proof of the defect.
        """
        defect_iid = "unassigned" if getUnassigned else str(self.getId())
        local_path = os.path.normpath(os.path.join(utils.getMainDir(), "files"))
        filepath = os.path.join(local_path, self.pentest, "proof", defect_iid)
        filepath = os.path.normpath(filepath)
        if not filepath.startswith(local_path):
            raise ValueError("Invalid path")
        return filepath

    def assignProof(self, filename: str):
        """
        Assign a proof to this defect and remove it from unassigned
        
        Args:
            filename (str): The filename of the proof to assign.
        
        """
        filename = str(filename)
        filename = DBClient.sanitize_filename(filename)
        filename = os.path.basename(filename)
        my_proof_dir = self.getProofPath()
        unassigned_proof_dir = self.getProofPath(True)
        proof_path = os.path.join(unassigned_proof_dir, filename)
        if not os.path.isfile(proof_path):
            raise FileNotFoundError("File not found")
        dbclient = DBClient.getInstance()
        dbclient.updateInDb(self.pentest, "defects", {"_id": ObjectId(self.getId())}, {"$addToSet":{"proofs":filename}})
        new_proof_path = os.path.join(my_proof_dir, filename)
        os.makedirs(my_proof_dir, exist_ok=True)
        shutil.move(proof_path, new_proof_path)

    def rmProof(self, filename: str) -> None:
        """
        Remove defect proof on disk and in the database

        Args:
            filename (str): The filename of the proof to remove.

        Raises:
            ValueError: If the file is not found.
        """
        filename = str(filename)
        filename = DBClient.sanitize_filename(filename)
        filename = os.path.basename(filename)
        proof_dir = self.getProofPath()
        proof_path = os.path.join(proof_dir, filename)
        if not os.path.isfile(proof_path):
            raise FileNotFoundError("File not found")
        dbclient = DBClient.getInstance()
        dbclient.updateInDb(self.pentest, "defects", {"_id": ObjectId(self.getId())}, {"$pull":{"proofs":filename}})
        dbclient.deleteFromDb(self.pentest, "attachments", {"attachment_id": filename, "attached_to": self.getId()}, many=True)
        os.remove(proof_path)

    def listProofFiles(self, getUnassigned=False) -> List[str]:
        """
        List all proofs for this defect.

        Args:
            getUnassigned (bool): get proof that are not assigned to a defect. Defaults to False.
        Raises:
            FileNotFoundError: If the proof path is not found.
            ValueError: If the proof path is invalid.
        Returns:
            List[str]: A list of all proofs for this defect.
        """
        try:
            proofpath = self.getProofPath(getUnassigned)
            files = os.listdir(proofpath)
        except FileNotFoundError as e:
            raise e
        except ValueError as e:
            raise e
        return files
