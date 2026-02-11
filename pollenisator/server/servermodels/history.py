"""
Handle generic history snapshot creation and retrieval
"""
from typing import Any, Dict, List, Tuple, Union
from datetime import datetime
from bson import ObjectId
from pollenisator.core.components.mongo import DBClient
from pollenisator.server.permission import permission

ErrorStatus = Tuple[str, int]

@permission("pentester")
def getHistory(pentest: str, entity_iid: str, collection: str) -> Union[List[Dict[str, Any]], Tuple[str, int]]:
    """
    Get the history snapshots for a specific entity.

    Args:
        pentest (str): The name of the pentest.
        entity_iid (str): The id of the entity to get history for.
        collection (str): The collection name (e.g., "ips", "ports", "scopes", "waves").

    Returns:
        Union[List[Dict[str, Any]], Tuple[str, int]]: List of history documents or error tuple.
    """
    if not collection:
        return "Missing 'collection' query parameter", 400
    dbclient = DBClient.getInstance()
    
    # Derive singular name for history reference field
    singular = collection.rstrip('s') if collection.endswith('s') else collection
    
    # Query history collection
    history_field = f"history_{singular}_iid"
    try:
        history = dbclient.findInDb(
            pentest,
            f"{collection}_history",
            {history_field: ObjectId(entity_iid)},
            multi=True
        )
        
        if history is None:
            return []
        
        # Convert to list and return
        return [doc for doc in history]
    except Exception as e:
        return str(e), 500

@permission("pentester")
def createSnapshot(pentest: str, entity_iid: ObjectId, body: Dict[str, Any], **kwargs: Dict[str, Any]) -> Tuple[bool, int]:
    """
    Create a snapshot of an entity in its history collection.
    The snapshot is saved to {collection}_history with metadata added.

    Args:
        pentest (str): The name of the pentest.
        entity_iid (ObjectId): The id of the entity to snapshot.
        body (Dict[str, Any]): The entity data to save in history (must include 'collection' field).
        **kwargs: Contains token_info with user information.

    Returns:
        Tuple[bool, int]: (True, 200) if successful, or error tuple.
    """
    username = kwargs["token_info"]["sub"]
    dbclient = DBClient.getInstance()
    
    # Extract collection from body
    collection = body.get("collection")
    if not collection:
        return "Missing 'collection' field in request body", 400
    
    # Derive singular name for history reference field
    # Simple rule: remove trailing 's' for most collections
    singular = collection.rstrip('s') if collection.endswith('s') else collection
    
    # Prepare history document
    history_data = body.copy()
    
    # Remove _id and collection from history data (collection is metadata, not entity data)
    if "_id" in history_data:
        del history_data["_id"]
    if "collection" in history_data:
        del history_data["collection"]
    
    # Add history metadata
    history_data[f"history_{singular}_iid"] = ObjectId(entity_iid)
    history_data["snapshot_date"] = datetime.now()
    history_data["snapshot_user"] = username
    history_data["entity_type"] = collection
    
    # Insert into history collection (with notify=False to avoid WebSocket spam)
    dbclient.insertInDb(
        pentest, 
        f"{collection}_history", 
        history_data, 
        notify=False
    )
    return True, 200
