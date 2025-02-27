"""
This module is a part of the Pollenisator project.
This module is responsible for managing the additional sections of a pentest report.
"""
import json
from typing import Any, Dict, List, Literal, Optional, Tuple, Union, cast
from typing_extensions import TypedDict
from bson import ObjectId
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.models.element import Element
from pymongo.results import InsertOneResult, UpdateResult
from pollenisator.server.permission import permission

AdditionalReportSectionResult = TypedDict('AdditionalReportSectionResult', {'res': bool, 'iid': Optional[ObjectId]})
ErrorStatus = Tuple[str, int]

class AdditionalReportSection(Element):
    """
    Represents an additional report section object.

    Attributes:
        coll_name: collection name in pollenisator or pentest database

    """
    coll_name = 'additionalreportsections'

    def __init__(self, valuesFromDb: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize an Additional report section object. If valuesFromDb is provided, it is used to initialize the object. 
        Otherwise, the object is initialized with default values.

        Args:
            pentest (str): The name of the current pentest.
            valuesFromDb (Optional[Dict[str, Any]], optional): The values from the database. Defaults to None.
        """
        if valuesFromDb is None:
            valuesFromDb = {}
        super().__init__("pollenisator", valuesFromDb)
        self.initialize(valuesFromDb.get("title", ""), valuesFromDb.get("description",""), valuesFromDb.get("jsonSchema", ""),
                        valuesFromDb.get("uiSchema", ""), valuesFromDb.get("formData", ""), valuesFromDb.get("section_type", "global"))

    def initialize(self, title: str = "", description: str = "", jsonSchema: str = "", uiSchema: str="", formData: str="", section_type: str="" ) -> 'AdditionalReportSection':
        """
        Initialize this Additional report section with the provided parameters.

        Args:
            title (str, optional): The title of this Additional report section. Defaults to "".
            description (str, optional): The description of this Additional report section. Defaults to "".
            jsonSchema (str, optional): The jsonSchema of this Additional report section. Defaults to "".
            uiSchema (str, optional): The uiSchema of this Additional report section. Defaults to "".
            formData (str, optional): The formData of this Additional report section. Defaults to "".
            section_type (str, optional): The type of this Additional report section. Defaults to "global"., options: global, defect, fix

        Raises:
            ValueError: If jsonSchema, uiSchema or formData is not a valid json
        Returns:
            AdditionalReportSection: The initialized AdditionalReportSection
        """
        self.title = title
        self.description = description
        self.jsonSchema = jsonSchema
        self.uiSchema = uiSchema
        self.formData = formData
        self.section_type = "global" if section_type is None else section_type 
        try:
            json.loads(self.jsonSchema)
        except json.JSONDecodeError as e:
            raise ValueError(f"jsonSchema is not a valid json string: {e}") from e
        try:
            json.loads(self.uiSchema)
        except json.JSONDecodeError as e:
            raise ValueError(f"uiSchema is not a valid json string: {e}") from e
        try:
            json.loads(self.formData)
        except json.JSONDecodeError as e:
            raise ValueError(f"formData is not a valid json string: {e}") from e
        return self

    def getData(self) -> Dict[str, Any]:
        """
        Get the data of this Additional report section object as a dictionary.

        Returns:
            Dict[str, Any]: The data of this Additional report section object.
        """
        return {"_id": self._id, "title":self.title, "description": self.description, "jsonSchema":self.jsonSchema, "uiSchema":self.uiSchema,
                 "formData":self.formData, "section_type":self.section_type }

    def addInDb(self) -> AdditionalReportSectionResult:
        """
        Add this  object to the database and return the id of the inserted document.

        Returns:
            AdditionalReportSectionResult: the result of the insert function
        """
        res: AdditionalReportSectionResult = insert(self.getData())
        return res

    

    def checkExistingSection(self) -> bool:
        """
        Check if a section with the same title already exists in the database.

        Returns:
            bool: True if a section with the same title already exists, False otherwise.
        """
        dbclient = DBClient.getInstance()
        section = dbclient.findInDb("pollenisator", AdditionalReportSection.coll_name, {"title": self.title}, multi=False)
        return section is not None


@permission("report_template_writer")
def insert( body: Dict[str, Any]) -> Union[ErrorStatus,AdditionalReportSectionResult]:
    """
    Insert a new report section.

    Args:
        body (Dict[str, Any]): The section information.

    Returns:
         Union[ErrorStatus,AdditionalReportSectionResult]: The result of the insert operation as a dict with result and iid.
    """
    section = AdditionalReportSection(body)
    dbclient = DBClient.getInstance()
    data = section.getData()
    if "_id" in data:
        del data["_id"]
    if (section.checkExistingSection()):
        return "A section with the same title already exists", 409
    if section.title.strip() == "":
        return "Title is required", 400
    ins_result = dbclient.insertInDb("pollenisator",
        AdditionalReportSection.coll_name, data, notify=True)
    ins_result = cast(InsertOneResult, ins_result)
    iid = ins_result.inserted_id
    return {"res": True, "iid": iid}

@permission("report_template_writer")   
def update( iid: str, body: Dict[str, Any]) ->  Union[ErrorStatus,AdditionalReportSectionResult]:
    """
    Update a report section.

    Args:
        iid (str): The id of the section to update.
        body (Dict[str, Any]): The section information.

    Returns:
        Union[ErrorStatus,AdditionalReportSectionResult]: The result of the update operation as a dict with result and iid.
    """
    section = AdditionalReportSection(body)
    if section.title.strip() == "":
        return "Title is required", 400
    dbclient = DBClient.getInstance()
    old_data = dbclient.findInDb("pollenisator", AdditionalReportSection.coll_name, {"_id": ObjectId(iid)}, multi=False)
    if old_data is None:
        return {"res": False, "iid": ObjectId(iid)}
    if old_data.get("title") != section.title:
        if (section.checkExistingSection()):
            return "A section with the same title already exists", 409
    data = section.getData()
    old_data |= data
    if "_id" in old_data:
        del old_data["_id"]
    object_iid = ObjectId(iid)
    update_result = dbclient.updateInDb("pollenisator",
        AdditionalReportSection.coll_name, {"_id": ObjectId(object_iid)}, {"$set":old_data}, notify=True)
    modified = update_result.modified_count
    if modified > 0:
        return {"res": True, "iid": object_iid}
    else:
        return {"res": False, "iid": object_iid}

@permission("report_template_writer")
def delete(iid: str) -> int:
    """
    Delete a report section.

    Args:
        iid (str): The id of the section to delete.

    Returns:
        int: The number of deleted sections.
    """
    dbclient = DBClient.getInstance()
    ins_result = dbclient.deleteFromDb("pollenisator",
        AdditionalReportSection.coll_name, {"_id": ObjectId(iid)}, notify=True)
    return ins_result


@permission("pentester")
def updateData(pentest: str, iid: str, body: Dict[str, Any]) -> Union[ErrorStatus, bool]:
    """
    Update the data of a report section.

    Args:
        pentest (str): The name of the current pentest.
        iid (str): The id of the section to update.
        body (Dict[str, Any]): The section information.

    Returns:
        Union[ErrorStatus, bool]: The result of the update operation.
    """
    if pentest == "pollenisator":
        return "Forbidden", 403
    dbclient = DBClient.getInstance()
    if "_id" in body:
        del body["_id"]
    if "section_id" in body:
        del body["section_id"]
    dbclient.updateInDb(pentest, "additionalreportsections", {"section_id": ObjectId(iid)}, {"$set": body}, many=False, upsert=True)
    return True

@permission("pentester")
def getData(pentest: str, iid: str) -> Union[ErrorStatus, Dict[str, Any]]:
    """
    Get the data of a report section.

    Args:
        pentest (str): The name of the current pentest.
        iid (str): The id of the section to get.

    Returns:
        Union[ErrorStatus, Dict[str, Any]]: The section data.
    """
    if pentest == "pollenisator":
        return "Forbidden", 403
    dbclient = DBClient.getInstance()
    section = dbclient.findInDb(pentest, "additionalreportsections", {"section_id": ObjectId(iid)}, multi=False)
    if section is None:
        return "Not found", 404
    return section

@permission("user")
def getById(iid: str) -> Union[ErrorStatus, Dict[str, Any]]:
    """
    Get a report section by id.

    Args:
        iid (str): The id of the section to get.

    Returns:
        Dict[str, Any]: The section object.
    """
    dbclient = DBClient.getInstance()
    section = dbclient.findInDb("pollenisator",
        AdditionalReportSection.coll_name, {"_id": ObjectId(iid)}, multi=False)
    if section is None:
        return "Not found", 404
    return section

@permission("user")
def listAll() -> List[Dict[str, Any]]:
    """
    Get all report section.

    Returns:
        List[AdditionalReportSection]: The section object.
    """
    dbclient = DBClient.getInstance()
    sections = dbclient.findInDb("pollenisator",
        AdditionalReportSection.coll_name, {}, multi=True)
    if sections is None:
        return []
    return [x for x in sections]
