"""
Generate and verify JWT tokens for the Pollenisator API.
"""
from typing import Any, Dict, List, Union, cast
import uuid
import datetime
from bson import ObjectId
import six
from werkzeug.exceptions import Unauthorized
from jose import JWTError, jwt
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.components.logger_config import logger

JWT_SECRET = str(uuid.uuid4())
JWT_LIFETIME_SECONDS = 3600*8
JWT_ALGORITHM = 'HS256'

def getTokenFor(username: str, pentest: str = "", owner: bool = False) -> str:
    """
    Get the token for a specific user. If the user does not have a token or if the token is invalid, a new token is generated.

    Args:
        username (str): The username of the user.
        pentest (str, optional): The pentest associated with the user. Defaults to "".
        owner (bool, optional): Whether the user is an owner. Defaults to False.

    Returns:
        str: The token for the user.
    """
    mongoinstance = DBClient.getInstance()
    user_record = mongoinstance.findInDb("pollenisator", "users", {"username":username}, False)
    if user_record is None:
        return ""
    mod = False
    try:
        scopes = set(decode_token(user_record.get("token","")).get("scope", []))
    except Unauthorized:
        scopes = set()
    scopes = scopes.union(set(user_record.get("scope", [])))
    if pentest != "" and pentest not in scopes:
        
        scopes.add(pentest)
        if owner:
            scopes.add("owner")
        scopes.add("pentester")
        mod = True
    if "user" not in scopes:
        scopes.add("user")
        mod = True
    if verifyToken(user_record.get("token", "")) and not mod:
        token = user_record.get("token", "")
    else:
        token = generateNewToken(user_record, list(scopes))
    return str(token)

def generateNewToken(user_record: Dict[str, Union[str, ObjectId]], new_scopes: List[str]) -> str:
    """
    Generate a new JWT token for a user.

    Args:
        user_record (Dict[str, Union[str, ObjectId]]): A dictionary containing the user's details.
            "_id" (ObjectId): The user's ID.
            "username" (str): The user's username.
        new_scopes (List[str]): A list of scopes the token is authorized for.

    Returns:
        str: The encoded JWT token.
    """
    # Get the current timestamp
    timestamp = _current_timestamp()

    # Construct the payload for the new token
    payload = {
        "iat": int(timestamp),  # Issued at time (in seconds since epoch)
        "exp": int(timestamp + JWT_LIFETIME_SECONDS),  # Expiry time (in seconds since epoch)
        "sub": str(user_record["username"]),  # Subject (username) of the token
        "scope": new_scopes,  # List of scopes the token is authorized for
    }

    # Encode the payload as a JWT
    jwt_encoded = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    # Update the user record in the database with the new token
    dbclient = DBClient.getInstance()
    dbclient.updateInDb("pollenisator", "users", {"_id":user_record["_id"]}, {"$set":{"token":jwt_encoded}}, notify=False)

    # Return the encoded JWT
    return str(jwt_encoded)


def verifyToken(access_token: str) -> bool:
    """
    Verify the validity of a JWT token.

    Args:
        access_token (str): The JWT token to verify.

    Returns:
        bool: True if the token is valid, False otherwise.
    """
    try:
        jwt_decoded = jwt.decode(access_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError as _e:
        return False
    return checkTokenValidity(jwt_decoded)

def checkTokenValidity(jwt_decoded: Dict[str, Any]) -> bool:
    """
    Check the validity of a decoded JWT token.

    Args:
        jwt_decoded (Dict[str,Any]): The decoded JWT token. It should contain an "exp" key with the expiration timestamp.

    Returns:
        bool: True if the token is valid and has not expired, False otherwise.
    """
    dbclient = DBClient.getInstance()
    access_token = encode_token(jwt_decoded)
    user = dbclient.findInDb("pollenisator", "users", {"token":access_token}, False)
    if user is not None:
        exp_timestamp = jwt_decoded.get("exp", datetime.datetime.now().timestamp())
        if datetime.datetime.now().timestamp() > exp_timestamp:
            return False
        return True
    return False

def encode_token(token_info: Dict[str, Any]) -> str:
    """
    Encode a dictionary into a JWT token.

    Args:
        token_info (Dict[str, Any]): The information to encode into the token. 
        This should include the "exp" key with the expiration timestamp and the "scopes" key with a list of scopes the token is authorized for.

    Returns:
        str: The encoded JWT token.
    """
    return str(jwt.encode(token_info, JWT_SECRET, algorithm=JWT_ALGORITHM))

def decode_token(token: str) -> Dict[str, Any]:
    """
    Decode a JWT token into a dictionary.

    Args:
        token (str): The JWT token to decode.

    Returns:
        Dict[str, Any]: The decoded token information.

    Raises:
        Unauthorized: If the token is invalid.
    """
    try:
        return cast(Dict[str, Any], jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM]))
    except JWTError as e:
        print("ERROR token "+str(e))
        logger.info("Unauthorized, token in Bearer is invalid : token (%s) error (%s)", token, e)
        six.raise_from(Unauthorized, e)
    return {}


def decode_cookie(token: str) -> Dict[str, Any]:
    """
    Decode a JWT token from cookie into a dictionary.

    Args:
        token (str): The JWT token to decode.

    Returns:
        Dict[str, Any]: The decoded token information.

    Raises:
        Unauthorized: If the token is invalid.
    """
    try:
        return cast(Dict[str, Any], jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM]))
    except JWTError as e:
        print("ERROR token in COOKIE"+str(e))
        logger.info("Unauthorized, token in COOKIE is invalid : token (%s) error (%s)", token, e)
        six.raise_from(Unauthorized, e)
    return {}

def _current_timestamp() -> float:
    """
    Returns the current timestamp as a float.
    
    Returns:
        float: The current timestamp.
    """
    return datetime.datetime.now().timestamp()
