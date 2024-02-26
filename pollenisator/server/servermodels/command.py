"""
handle the command related API calls
"""

from typing import Dict, Any, List, Union, Tuple
from typing_extensions import TypedDict
from bson import ObjectId
import json
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.models.command import Command
from pollenisator.core.components.utils import JSONDecoder
from pollenisator.server.permission import permission

CommandInsertResult = TypedDict('CommandInsertResult', {'res': bool, 'iid': ObjectId})

@permission("user")
def getCommands(body: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Get commands from the database based on the provided pipeline.

    Args:
        body (Dict[str, Any]): A dictionary containing the pipeline for the database query.

    Returns:
        List[Dict[str, Any]]: A list of commands fetched from the database.
    """
    pipeline = body.get("pipeline", {})
    if isinstance(pipeline, str):
        pipeline = json.loads(pipeline, cls=JSONDecoder)
    dbclient = DBClient.getInstance()
    results = dbclient.findInDb("pollenisator", "commands", pipeline, True)
    if results is None:
        return []
    return [x for x in results]

@permission("user")
def deleteCommand(command_iid: str, **kwargs: Any) -> Union[Tuple[str, int],int]:
    """
    Delete a command from the database using its id.

    Args:
        command_iid (str): The id of the command to be deleted.
        **kwargs (Any): Additional keyword arguments.

    Returns:
        Union[Tuple[str, int], int]: A tuple containing an error message and status code if the command is not found,
        otherwise the result count of the deletion operation.
    """
    dbclient = DBClient.getInstance()
    c = dbclient.findInDb("pollenisator",
        "commands", {"_id": ObjectId(command_iid)}, False)
    if c is None:
        return "Not found", 404
    command = Command("pollenisator", c)
    return command.deleteFromDb()

@permission("pentester")
def delete(pentest: str, command_iid: str, **kwargs: Any) -> Union[Tuple[str, int], int]:
    """
    Delete a command from the database using its id.

    Args:
        pentest (str): The name of the pentest.
        command_iid (str): The id of the command to be deleted.
        **kwargs (Any): Additional keyword arguments.

    Returns:
        Union[Tuple[str, int], int]: A tuple containing an error message and status code if the command is not found,
        otherwise the result of the deletion operation.
    """
    dbclient = DBClient.getInstance()
    c = dbclient.findInDb(pentest,
        "commands", {"_id": ObjectId(command_iid)}, False)
    if c is None:
        return "Not found", 404
    command = Command(pentest, c)
    return command.deleteFromDb()


@permission("pentester")
def insert(pentest: str, body: Dict[str, Any], **kwargs: Any) -> CommandInsertResult:
    """
    Insert a new command into the database. The user who owns the command is extracted from the token info.

    Args:
        pentest (str): The name of the pentest.
        body (Dict[str, Any]): A dictionary containing the command details.
        **kwargs (Any): Additional keyword arguments, including the token info.

    Returns:
        CommandInsertResult: A dictionary containing the result of the operation and the id of the inserted command.
    """
    user = kwargs["token_info"]["sub"]
    body["owners"] = [str(user)]
    command_o = Command(pentest, body)
    return command_o.addInDb()


@permission("pentester")
def update(pentest: str, command_iid: str, body: Dict[str, Any], **kwargs: Any) -> bool:
    """
    Update a command in the database using its id. The "owners" and "_id" fields in the body are ignored.

    Args:
        pentest (str): The name of the pentest.
        command_iid (str): The id of the command to be updated.
        body (Dict[str, Any]): A dictionary containing the new command details.
        **kwargs (Any): Additional keyword arguments.

    Returns:
        bool: True if the operation was successful, False otherwise.
    """
    dbclient = DBClient.getInstance()
    command = Command(pentest, dbclient.findInDb(pentest, "commands", {"_id": ObjectId(command_iid)}, False))
    if "owners" in body:
        del body["owners"]
    if "_id" in body:
        del body["_id"]
    dbclient.updateInDb(command.indb, "commands", {"_id": ObjectId(command_iid)}, {"$set": body}, False, True)
    return True

@permission("user")
def addToMyCommands(command_iid: str, **kwargs: Any) -> Tuple[str, int]:
    """
    Add a command to the user's commands list. The user is extracted from the token info.

    Args:
        command_iid (str): The id of the command to be added.
        **kwargs (Any): Additional keyword arguments, including the token info.

    Returns:
        Tuple[str, int: A tuple containing an error message and status code if the command is not found,
        otherwise a string indicating the operation was successful and status code 200.
    """
    user = kwargs["token_info"]["sub"]
    dbclient = DBClient.getInstance()
    res = dbclient.findInDb("pollenisator", "commands", {
                                 "_id": ObjectId(command_iid)}, False)
    if res is None:
        return "Not found", 404
    dbclient.updateInDb("pollenisator", "commands", {
                                 "_id": ObjectId(command_iid)}, {"$push":{"owners":user}})
    return "OK", 200
