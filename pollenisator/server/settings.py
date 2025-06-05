"""Settings module"""
import json
from typing import Any, Dict, Tuple, Union
from typing_extensions import TypedDict
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.models.scope import Scope
from pollenisator.server.permission import permission
from pollenisator.core.components.utils import JSONDecoder

SettingDict = TypedDict('SettingDict', {'key': str, 'value': Any})
ErrorStatus = Tuple[str, int]

@permission("pentester")
def upsert(pentest: str, body: Dict[str, Any]) -> ErrorStatus:
    """
    Update an existing setting or insert a new setting if it does not exist.

    Args:
        pentest (str): The pentest associated with the setting.
        body (Dict[str, Any]): A dictionary containing the details of the setting.

    Returns:
        ErrorStatus: The result of the database operation.
    """
    dbclient = DBClient.getInstance()
    body = json.loads(json.dumps(body), cls=JSONDecoder)
    key = body.get("key", "")
    if key.lower() == "pentesters":
        return "Key argument was not valid", 400
    value = json.loads(body.get("value", ""))
    if key == "" or not isinstance(key, str):
        return "Key argument was not valid", 400
    res = dbclient.updateInDb(pentest, "settings", {"key":key}, {"$set":{"value":value}}, notify=False, upsert=True)
    if res.acknowledged and res.matched_count == 1: # update success
        if key.startswith("include_") and res.modified_count == 1:  # updated value is different
            Scope.updateScopesSettings(pentest)
    return "Success", 200

@permission("pentester")
def find(pentest: str, key: str) -> Union[ErrorStatus, SettingDict]:
    """
    Find a specific setting in the database.

    Args:
        pentest (str): The pentest associated with the setting.
        key (str): The key of the setting to find.

    Returns:
        Union[ErrorStatus, SettingDict]: If the key is not valid, returns an error message and status code. Otherwise, returns the result of the database operation.
    """
    if key == "" or not isinstance(key, str):
        return "Key argument was not valid", 400
    dbclient = DBClient.getInstance()
    res = dbclient.findInDb(pentest, "settings", {"key":key}, False)
    if res is None:
        return "Setting not found", 404
    return {"key": res["key"], "value": res["value"]}
