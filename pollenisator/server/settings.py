from pollenisator.core.components.mongo import DBClient
from pollenisator.server.permission import permission
import json
from pollenisator.core.components.utils import JSONDecoder, JSONEncoder
from pollenisator.server.servermodels.scope import ServerScope

@permission("pentester")
def upsert(pentest, body):
    dbclient = DBClient.getInstance()
    key = body.get("key", "")
    value = json.loads(body.get("value", ""))
    if key == "" or not isinstance(key, str):
        return "Key argument was not valid", 400
    res = dbclient.updateInDb(pentest, "settings", {"key":key}, {"$set":{"value":value}}, notify=False, upsert=True)
    if key.startswith("include_"):
        ServerScope.updateScopesSettings(pentest)
    return True

@permission("pentester")
def find(pentest, key):
    if key == "" or not isinstance(key, str):
        return "Key argument was not valid", 400
    dbclient = DBClient.getInstance()
    res = dbclient.findInDb(pentest, "settings", {"key":key}, False)
    return res