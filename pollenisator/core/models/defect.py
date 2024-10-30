"""Defect Model."""

from datetime import datetime
import os
import re
import shutil
import threading
from typing import Any, Dict, Iterator, List, Optional, Tuple, Union, cast
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

    def __init__(self, pentest: str, valuesFromDb: Optional[Dict[str, Any]] = None) -> None:
        """
        Constructor to initialize the Defect object.

        Args:
            pentest (str): An object representing a penetration test.
            valuesFromDb (Optional[Dict[str, Any]], optional): A dict holding values to load into the object. 
                A mongo fetched defect is optimal. Possible keys with default values are : _id (None), parent (None), 
                infos({}), target_id, target_type, title(""), synthesis(""), description(""), ease(""), impact(""), 
                risk(""), redactor("N/A"), type([]),  language(""),, notes(""), proofs([]), fixes([]), creation_time, 
                redact_state("New"),infos, index(None),  perimeter([]). Defaults to None.
        """
        if valuesFromDb is None:
            valuesFromDb = {}
        super().__init__(pentest, valuesFromDb)
        self.proofs: List[str] = []
        self.creation_time: Optional[datetime] = None
        self.index = 0
        if valuesFromDb is not None:
            self.initialize(valuesFromDb.get("target_id", None), valuesFromDb.get("target_type", ""),
                            valuesFromDb.get("title", ""), valuesFromDb.get("synthesis", ""), valuesFromDb.get("description", ""),
                            valuesFromDb.get("ease", ""), valuesFromDb.get(
                                "impact", ""),
                            valuesFromDb.get(
                                "risk", ""), valuesFromDb.get("redactor", "N/A"), valuesFromDb.get("type", []),
                            valuesFromDb.get("language", ""),
                            valuesFromDb.get("notes", ""), valuesFromDb.get(
                                "proofs", []),
                            valuesFromDb.get("fixes", []), valuesFromDb.get("creation_time", None), valuesFromDb.get("redacted_state", "New"),
                            valuesFromDb.get("infos", {}),
                            valuesFromDb.get("index", 0), valuesFromDb.get("perimeter", []))

    def initialize(self, target_id: Optional[ObjectId] = None, target_type: str = "", title: str = "", synthesis: str = "",
                   description: str = "", ease: str = "", impact: str = "", risk: str = "", redactor: str = "N/A",
                   mtype: Optional[Union[str, List[str]]] = None, language: str = "", notes: str = "",
                   proofs: Optional[List[str]] = None, fixes: Optional[List[Dict[str, Any]]] = None,
                   creation_time: Optional[datetime] = None, redacted_state: str = "New", infos: Optional[Dict[str, Any]] = None,
                   index: int = 0, perimeter: Optional[List[str]] = None) -> 'Defect':
        """
        Set values of defect.

        Args:
            target_id (Optional[ObjectId], optional): Defect will be assigned to this target_id. Defaults to "".
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
            redacted_state (str, optional): The redacted state of this defect. Defaults to "New".
            infos (Optional[Dict[str, Any]], optional): A dictionary with key values as additional information. Default to None.
            index (int, optional): The index of this defect in global defect table (only for unassigned defect). Defaults to 0.
            perimeter (Optional[List[str]], optional): A list of perimeters for this defect. Defaults to None.
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
        self.repr_string = self.getDetailedString()

        return self

    def getData(self) -> Dict[str, Any]:
        """
        Return defect attributes as a dictionary matching Mongo stored defects.

        Returns:
            Dict[str,Any]: A dictionary with keys title, 
            synthesis, description, ease, impact, risk, redactor, type, language, notes, target_id, target_type, index, 
            proofs, creation_time, redacted_state, fixes, _id, infos.
        """

        return {"title": self.title, "synthesis":self.synthesis, "description":self.description, "ease": self.ease, "impact": self.impact,
                "risk": self.risk, "redactor": self.redactor, "type": self.mtype, "language":self.language, "notes": self.notes,
                "target_id": self.target_id, "target_type": self.target_type, "index":int(self.index),
                "proofs": self.proofs, "creation_time": self.creation_time, "redacted_state":self.redacted_state, "fixes":self.fixes, "perimeter":self.perimeter, "_id": self.getId(), "infos": self.infos}

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
        return self.target_id is not None

    def addInDb(self) -> DefectInsertResult:
        """
        Add this defect into database.

        Raises:
            ValueError: If the target_id is not specified but the target_type is.

        Returns:
            DefectInsertResult: The ObjectId of the inserted document in the database, or None if the operation was not successful.
        """
        try:
            self.creation_time = datetime.now()
            self.redacted_state = "New" if self.redacted_state == "" or self.redacted_state is None else self.redacted_state
            if not self.isAssigned():
                sem.acquire()
            base = self.getDbKey()
            existing = Defect.fetchObject(self.pentest, base)
            if existing is not None:
                sem.release()
                return {"res":False, "iid": existing.getId()}
            if self.target_id is not None and self.target_type == "":
                sem.release()
                raise ValueError("If a target_id is specified, a target_type should be specified to")
            parent = self.getParentId()
            if self.pentest != "pollenisator" and not self.isAssigned():
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

            self.creation_time = datetime.now()
            if isinstance(self.mtype, str):
                self.mtype = self.mtype.split(",")
            dbclient = DBClient.getInstance()
            data = self.getData()
            if "_id" in data:
                del data["_id"]
            ins_result = dbclient.insertInDb(self.pentest, "defects", data, ObjectId(parent))
            iid = ins_result.inserted_id
            self._id = iid
            if self.pentest != "pollenisator":
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
            if self.isAssigned():
                # Edit to global defect and insert it
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
        except Exception as e:
            sem.release()
            raise(e)
        sem.release()
        return {"res":True, "iid":iid}

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
        if not self.isAssigned() and self.pentest != "pollenisator":
            # if not assigned to a pentest object it's a report defect (except in pollenisator db where it's a defect template)
            globalDefects_iterator = Defect.fetchObjects(self.pentest, {"target_id":None})
            if globalDefects_iterator is None:
                globalDefects: List[Defect] = []
            else:
                globalDefects = cast(List[Defect], globalDefects_iterator)
            for globalDefect in globalDefects:
                globalDefect = cast(Defect, globalDefect)
                if int(globalDefect.index) > int(self.index):
                    globalDefect.update_index(int(globalDefect.index)-1)
            thisAssignedDefects = Defect.fetchObjects(self.pentest, {"global_defect": ObjectId(self.getId())})
            if thisAssignedDefects is not None:
                for thisAssignedDefect in thisAssignedDefects:
                    thisAssignedDefect = cast(Defect, thisAssignedDefect)
                    thisAssignedDefect.deleteFromDb()
        if self.pentest != "pollenisator":
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
        res = dbclient.deleteFromDb(self.pentest, "defects", {"_id": ObjectId(self.getId())}, False)
        if res is None:
            return 0
        else:
            return res
        
    def save_review(self, data) -> None:
        """
        Save current version in the database under the version collection.

        """ 
        dbclient = DBClient.getInstance()
        new_data = self.getData()
        data = {} if data is None else data
        new_data |= data
        new_self = Defect(self.pentest, new_data)
        new_data = new_self.getData()
        
        new_data["defect_iid"] = new_data["_id"]
        if "_id" in new_data:
            del new_data["_id"]
        new_data["time"] = datetime.now()
        dbclient.updateInDb(self.pentest, "defectsreviews", {"defect_iid": new_data["defect_iid"]}, {"$set":new_data}, upsert=True)

    def get_review(self) -> Dict[str, Any]:
        """
        Get the version of this defect from the database.

        Returns:
            Dict[str, Any]: A dictionary representing the version of this defect.
        """
        dbclient = DBClient.getInstance()
        version = dbclient.findInDb(self.pentest, "defectsreviews", {"defect_iid": ObjectId(self.getId())}, multi=False)
        if version is not None:
            return version
        # if not found, create it
        defect = dbclient.findInDb(self.pentest, "defects", {"_id":ObjectId(self.getId())}, False)
        if defect is not None:
            defect["defect_iid"] = defect["_id"]
            del defect["_id"]
            dbclient.insertInDb(self.pentest, "defectsreviews", defect)
            return defect
        return {}

    def updateInDb(self, data: Optional[Dict[str, Any]] = None) -> list[str]:
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
        new_data |= data
        new_self = Defect(self.pentest, new_data)

        if "_id" in new_data:
            del new_data["_id"]
        oldRisk = self.risk
        if not new_self.isAssigned() and self.pentest != "pollenisator":
            if data.get("risk", None) is not None and self.pentest != "pollenisator":
                if new_data["risk"] != oldRisk:
                    insert_pos = Defect.findInsertPosition(self.pentest, new_data["risk"])
                    if int(insert_pos) > int(self.index):
                        insert_pos = int(insert_pos)-1
                    defectTarget = Defect.fetchObject(self.pentest, {"target_id":None, "index":insert_pos})
                    if defectTarget is not None:
                        Defect.moveDefect(self.pentest, self.getId(), defectTarget.getId())
                if "index" in new_data:
                    del new_data["index"]
        if self.pentest != "pollenisator" and "description" in data:
            new_data["proofs"] = set()
            proof_groups = Defect._findProofsInDescription(new_data.get("description", ""))
            try:
                existing_proofs_to_remove = self.listProofFiles()
            except FileNotFoundError:
                existing_proofs_to_remove = []
            for proof_group in proof_groups:
                if proof_group.group(1) in existing_proofs_to_remove:
                    existing_proofs_to_remove.remove(proof_group.group(1))
                new_data["proofs"].add(proof_group.group(1))
            for proof_to_remove in existing_proofs_to_remove:
                self.rmProof(proof_to_remove)
            new_data["proofs"] = list(new_data["proofs"])
        
        dbclient.updateInDb(self.pentest, "defects", {"_id":ObjectId(self.getId())}, {"$set":new_data}, False, True)
        return list(new_data.keys())

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
        riskLevels = ["Critical", "Major",  "Important", "Minor"] # TODO do not hardcode those things
        riskLevelPos = riskLevels.index(risk)
        highestInd = 0
        for risklevel_i, riskLevel in enumerate(riskLevels):
            if risklevel_i > riskLevelPos:
                break
            globalDefects = Defect.fetchObjects(pentest, {"target_id":None, "risk":riskLevel})
            globalDefects = cast(Iterator[Defect], globalDefects)
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
            del data["_id"]
        data = Defect(self.pentest, data).getData()
        if "_id" in data:
            del data["_id"]

        dbclient = DBClient.getInstance()
        oldRisk = self.risk
        if not self.isAssigned() and self.pentest != "pollenisator":
            if data.get("risk", None) is not None and self.pentest != "pollenisator":
                if data["risk"] != oldRisk:
                    insert_pos = Defect.findInsertPosition(self.pentest, data["risk"])
                    if int(insert_pos) > int(self.index):
                        insert_pos = int(insert_pos)-1
                    defectTarget = Defect.fetchObject(self.pentest, {"target_id":None, "index":insert_pos})
                    if defectTarget is not None:
                        Defect.moveDefect(self.pentest, self.getId(), defectTarget.getId())
                if "index" in data:
                    del data["index"]
        if self.pentest != "pollenisator":
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
        dbclient.updateInDb(self.pentest, "defects", {"_id":ObjectId(self.getId())}, {"$set":data})
        return True

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
        filename = os.path.basename(filename.replace("/", "_"))
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
        filename = os.path.basename(filename.replace("/", "_"))
        proof_dir = self.getProofPath()
        proof_path = os.path.join(proof_dir, filename)
        if not os.path.isfile(proof_path):
            raise FileNotFoundError("File not found")
        dbclient = DBClient.getInstance()
        dbclient.updateInDb(self.pentest, "defects", {"_id": ObjectId(self.getId())}, {"$pull":{"proofs":filename}})
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
