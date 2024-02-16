"""
handle the command related API calls
"""

from typing import Dict, Any, List, Union, Tuple, Optional
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

def doDelete(pentest: str, command: Command) -> int:
    """
    Delete a command from the database and remove all references to it.

    Args:
        pentest (str): The name of the pentest.
        command (Command): The command object to be deleted.

    Returns:
        Union[int, Any]: 0 if the deletion was unsuccessful, otherwise the result of the deletion operation.
    """
    dbclient = DBClient.getInstance()
    #TODO : delete from checks
    pentests = set(pentest)
    # Remove from all waves this command.
    if command.indb == "pollenisator":
        pentest_uuids = dbclient.listPentestUuids()
        if pentest_uuids is not None:
            pentests.union(pentest_uuids)
    else:
        pentests.add(command.indb)

    for pentest in pentests:
        waves = dbclient.findInDb(pentest, "waves", {}, True)
        for wave in waves:
            toBeUpdated = wave["wave_commands"]
            if command._id in wave["wave_commands"]:
                toBeUpdated.remove(command._id)
                dbclient.updateInDb(pentest, "waves", {"_id": wave["_id"]}, {
                    "$set": {"wave_commands": toBeUpdated}}, False)
        # Remove all tools refering to this command's name.
        dbclient.deleteFromDb(pentest,
                                   "tools", {"name": command.name}, True, True)
    res: int = dbclient.deleteFromDb(command.indb, "commands", {
        "_id": ObjectId(command._id)}, False, True)
    if res is None:
        return 0
    else:
        return res

@permission("user")
def deleteCommand(command_iid: str, **_kwargs: Any) -> Union[Tuple[str, int],int]:
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
    return doDelete("pollenisator", command)

@permission("pentester")
def delete(pentest: str, command_iid: str, **_kwargs: Any) -> Union[Tuple[str, int], int]:
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
    return doDelete(pentest, command)


def doInsert(_pentest: str, body: Dict[str, Any], user: str) -> CommandInsertResult:
    """
    Insert a new command into the database. If a command with the same name already exists, 
    the function will return the id of the existing command.

    Args:
        _pentest (str): The name of the pentest.
        body (Dict[str, Any]): A dictionary containing the command details.
        user (str): The name of the user who owns the command.

    Returns:
        CommandInsertResult: A dictionary containing the result of the operation and the id of the inserted command.
    """
    dbclient = DBClient.getInstance()
    existing = dbclient.findInDb(
        body["indb"], "commands", {"name": body["name"]}, False)
    if existing is not None:
        return {"res": False, "iid": existing["_id"]}
    if "_id" in body:
        del body["_id"]
    body["owners"] = [user]
    ins_result = dbclient.insertInDb(
        body["indb"], "commands", body, '', True)
    iid = ins_result.inserted_id
    return {"res": True, "iid": iid}

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
    return doInsert(pentest, body, user)


@permission("pentester")
def update(pentest: str, command_iid: str, body: Dict[str, Any], **_kwargs: Any) -> bool:
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

def addUserCommandsToPentest(pentest: str, user: str) -> bool:
    """
    Add all commands owned by a user to the pentest database.

    Args:
        pentest (str): The name of the pentest.
        user (str): The name of the user whose commands will be added.

    Returns:
        bool: True if the operation was successful, False otherwise.
    """
    """Add all commands owned by user to pentest database."""
    dbclient = DBClient.getInstance()
    commands = dbclient.findInDb(
        "pollenisator", "commands", {}, True)
    for command in commands:
        mycommand = command
        mycommand["original_iid"] = str(command["_id"])
        mycommand["indb"] = pentest
        res = doInsert(pentest, mycommand, user)
        if not res["res"]:
            dbclient.updateInDb(pentest, "commands", {
                                 "_id": ObjectId(res["iid"])}, {"$push":{"owners":user}})
    return True
