"""Handle notification related API calls."""
from typing import Any, Dict, List, Tuple, Union
from typing_extensions import TypedDict
from bson import ObjectId
from datetime import datetime
from pollenisator.core.components.mongo import DBClient
from pollenisator.server.permission import permission
from pollenisator.core.components.logger_config import logger

NotificationCreateResult = TypedDict('NotificationCreateResult', {
    'success': bool, 
    'notification_id': str
})

ErrorStatus = Tuple[str, int]


@permission("pentester", "body.pentest")
def create(body: Dict[str, Any], **kwargs: Dict[str, Any]) -> Union[NotificationCreateResult, ErrorStatus]:
    """
    Create a new review notification and emit Socket.IO event.
    
    Args:
        body (Dict[str, Any]): Request body containing notification details
        **kwargs: Additional keyword arguments including token_info
        
    Returns:
        Union[NotificationCreateResult, ErrorStatus]: Success result with notification ID or error tuple
    """
    try:
        # Validate required fields
        required_fields = ['pentest', 'entity_type', 'entity_id', 
                          'entity_name', 'target_user']
        for field in required_fields:
            if field not in body:
                return f'Missing required field: {field}', 400
        
        # Get requesting user from token
        requesting_user = kwargs["token_info"]["sub"]
        
        dbclient = DBClient.getInstance()
        
        # Verify target_user exists in the system
        target_user_record = dbclient.getUserRecordFromUsername(body['target_user'])
        if target_user_record is None:
            return f"Target user '{body['target_user']}' not found", 404
        
        # Verify target_user is part of the pentest
        pentest_users = dbclient.getPentestUsers(body['pentest'])
        if body['target_user'] not in pentest_users:
            return f"Target user '{body['target_user']}' is not a member of this pentest", 403
        
        # Create notification document
        notification = {
            'pentest_id': body['pentest'],
            'entity_type': body['entity_type'],
            'entity_id': ObjectId(body['entity_id']),
            'entity_name': body['entity_name'],
            'requested_by': requesting_user,
            'target_user': body['target_user'],
            'read': False,
            'created_at': datetime.utcnow().isoformat()
        }
        
        # Insert into global pollenisator database
        result = dbclient.insertInDb(body['pentest'], "user_notifications", 
                                     notification, notify=False)
        
        # Emit Socket.IO event to pentest room
        dbclient.send_notify(body['pentest'], "user_notifications", result.inserted_id, "insert")
        return {
            'success': True,
            'notification_id': str(result.inserted_id)
        }
        
    except Exception as e:
        return str(e), 500


@permission("pentester")
def getNotifications(pentest: str, username: str, **kwargs: Dict[str, Any]) -> Union[List[Dict[str, Any]], ErrorStatus]:
    """
    Get all unread notifications for a specific user in a pentest.
    Users can only fetch their own notifications unless they are admin.
    
    Args:
        pentest(str): The pentest identifier
        username (str): The username to fetch notifications for
        **kwargs: Additional keyword arguments including token_info
        
    Returns:
        Union[List[Dict[str, Any]], ErrorStatus]: List of notifications or error tuple
    """
    try:
        # Verify user can access this pentest
        token_info = kwargs["token_info"]
        requesting_user = token_info["sub"]
        
        # Users can only fetch their own notifications unless admin
        if requesting_user != username and "admin" not in token_info.get("scope", []):
            return "Forbidden: can only access your own notifications", 403
        
        dbclient = DBClient.getInstance()
        notifications = dbclient.findInDb(pentest, "user_notifications", {
            'pentest_id': pentest,
            'target_user': username,
            'read': False
        }, multi=True)
        
        if notifications is None:
            return []
        
        # Convert ObjectIds to strings for JSON serialization
        result = []
        for notif in notifications:
            notif['_id'] = str(notif['_id'])
            notif['entity_id'] = str(notif['entity_id'])
            result.append(notif)
        
        return result
        
    except Exception as e:
        return str(e), 500


@permission("pentester")
def markAsRead(pentest:str, notification_id: str, **kwargs: Dict[str, Any]) -> Union[Dict[str, bool], ErrorStatus]:
    """
    Mark a notification as read.
    Users can only mark their own notifications as read unless they are admin.
    
    Args:
        pentest (str): The pentest identifier
        notification_id (str): The notification ObjectId as string
        **kwargs: Additional keyword arguments including token_info
        
    Returns:
        Union[Dict[str, bool], ErrorStatus]: Success result or error tuple
    """
    try:
        dbclient = DBClient.getInstance()
        
        # Verify notification belongs to requesting user
        token_info = kwargs["token_info"]
        requesting_user = token_info["sub"]
        
        notification = dbclient.findInDb(pentest, "user_notifications", 
                                        {'_id': ObjectId(notification_id), "pentest_id":pentest}, False)
        if notification is None:
            return 'Notification not found', 404
        
        # Verify ownership unless admin
        if notification['target_user'] != requesting_user and "admin" not in token_info.get("scope", []):
            return "Forbidden: can only mark your own notifications as read", 403
        
        result = dbclient.updateInDb(pentest, "user_notifications",
                                     {'_id': ObjectId(notification_id)},
                                     {'$set': {'read': True}}, notify=False)
        
        if result.matched_count == 0:
            return 'Notification not found', 404
        
        return {'success': True}
        
    except Exception as e:
        return str(e), 500


@permission("pentester")
def delete(pentest:str, notification_id: str, **kwargs: Dict[str, Any]) -> Union[Dict[str, bool], ErrorStatus]:
    """
    Hard delete a notification.
    Users can only delete their own notifications unless they are admin.
    
    Args:
        notification_id (str): The notification ObjectId as string
        **kwargs: Additional keyword arguments including token_info
        
    Returns:
        Union[Dict[str, bool], ErrorStatus]: Success result or error tuple
    """
    try:
        dbclient = DBClient.getInstance()
        
        # Verify notification belongs to requesting user
        token_info = kwargs["token_info"]
        requesting_user = token_info["sub"]
        
        notification = dbclient.findInDb(pentest, "user_notifications", 
                                        {'_id': ObjectId(notification_id)}, False)
        if notification is None:
            return 'Notification not found', 404
        
        # Verify ownership unless admin
        if notification['target_user'] != requesting_user and "admin" not in token_info.get("scope", []):
            return "Forbidden: can only delete your own notifications", 403
        
        dbclient.deleteFromDb(pentest, "user_notifications",
                                       {'_id': ObjectId(notification_id)}, 
                                       many=False, notify=False)
        

        
        return {'success': True}
        
    except Exception as e:
        return str(e), 500
