#!/usr/bin/env python3

"""
Module for the authentication and user management.
"""

from typing import Any, Dict, List, Tuple, Union
from pollenisator.core.components.mongo import DBClient
import bcrypt
from pollenisator.server.permission import permission
from pollenisator.server.token import getTokenFor
from pollenisator.server.mongo import doImportCheatsheet
from pollenisator.core.components.utils import getDefaultCheatsheetFile

ErrorStatus = Tuple[str, int]
@permission("admin")
def createUser(body: Dict[str, str]) -> ErrorStatus:
    """
    Create a new user with the given details.

    Args:
        body (Dict[str, str]): A dictionary containing the user's details.
            "username" (str): The username of the new user.
            "name" (str): The name of the new user.
            "surname" (str): The surname of the new user.
            "email" (str): The email of the new user.
            "pwd" (str): The password of the new user.

    Returns:
        ErrorStatus: A success message if the user was successfully created, otherwise an error message and status code.
    """
    username = body.get("username", "")
    name = body.get("name", "")
    surname = body.get("surname", "")
    email = body.get("email", "")
    pwd = body.get("pwd", "")
    if username == "":
        return "username is required", 400
    elif pwd == "":
        return "pwd is required", 400
    dbclient = DBClient.getInstance()
    user = dbclient.findInDb("pollenisator", "users", {"username":username}, False)
    if user is not None:
        return "A user with this username already exists", 403
    salt = bcrypt.gensalt()
    dbclient.insertInDb("pollenisator", "users", {"username":username, "hash":bcrypt.hashpw(pwd.encode(), salt), "name":name, "surname":surname, "email":email, "scope":["user"]})
    return "Successully created user", 200


@permission("admin")
def updateUserInfos(body: Dict[str, str]) -> ErrorStatus:
    """
    Update the details of an existing user.

    Args:
        body (Dict[str, str]): A dictionary containing the new user details.
            "username" (str): The username of the user to update.
            "name" (str, optional): The new name of the user.
            "surname" (str, optional): The new surname of the user.
            "email" (str, optional): The new email of the user.

    Returns:
        ErrorStatus: A success message if the user was successfully updated, otherwise an error message and status code.
    """
    username = body.get("username", "")
    if username == "":
        return "Username is required", 400
    dbclient = DBClient.getInstance()
    user = dbclient.findInDb("pollenisator", "users", {"username":username}, False)
    if user is None:
        return "User not found", 404
    name = body.get("name", user.get("name",""))
    surname = body.get("surname", user.get("surname",""))
    email = body.get("email", user.get("email",""))
    dbclient.updateInDb("pollenisator", "users", {"username":username}, {"$set":{"name":name, "surname":surname, "email":email}})
    return "Successully created user", 200

@permission("admin")
def deleteUser(username: str) -> ErrorStatus:
    """
    Delete an existing user.

    Args:
        username (str): The username of the user to delete.

    Returns:
        ErrorStatus: A success message if the user was successfully deleted, otherwise an error message and status code.
    """
    dbclient = DBClient.getInstance()
    user = dbclient.findInDb("pollenisator", "users", {"username":username}, False)
    if user is not None:
        dbclient.deleteFromDb("pollenisator", "users", {"username":username}, False, False)
        return "User successfully deleted", 200
    else:
        return "User to delete not found", 404

@permission("user")
def changePassword(body: Dict[str, str], **kwargs: Any) -> ErrorStatus:
    """
    Change the password of the current user.

    Args:
        body (Dict[str, str]): A dictionary containing the old and new passwords.
            "oldPwd" (str): The old password.
            "newPwd" (str): The new password.
        **kwargs (Any): Additional parameters, including the user token.

    Returns:
       ErrorStatus: A success message if the password was successfully changed, otherwise an error message and status code.
    """
    thisUser = kwargs["token_info"]["sub"]
    oldPwd = body.get("oldPwd", "")
    newPwd = body.get("newPwd", "")
    if oldPwd == "":
        return "oldPwd is required", 400
    elif newPwd == "":
        return "newPwd is required", 400
    username = thisUser
    dbclient = DBClient.getInstance()
    user_record = dbclient.findInDb("pollenisator", "users", {"username":username}, False)
    if user_record is None:
        return "This user does not exist", 404
    salt = bcrypt.gensalt()
    if not bcrypt.checkpw(oldPwd.encode(), user_record["hash"]):
        return "The old password is incorrect", 403
    hashed = bcrypt.hashpw(newPwd.encode(), salt)
    dbclient.updateInDb("pollenisator", "users", {"username":username}, {"$set":{"hash":hashed}}, False)
    return "Success", 200

@permission("admin")
def resetPassword(body: Dict[str, str]) -> ErrorStatus:
    """
    Reset the password of an existing user.

    Args:
        body (Dict[str, str]): A dictionary containing the username and the new password.
            "username" (str): The username of the user.
            "newPwd" (str): The new password.
    
    Returns:
        ErrorStatus: A success message if the password was successfully reset, otherwise an error message and status code.
    """
    username = body.get("username", "")
    newPwd = body.get("newPwd", "")
    if username == "":
        return "username is required", 400
    elif newPwd == "":
        return "newPwd is required", 400
    dbclient = DBClient.getInstance()
    user_record = dbclient.findInDb("pollenisator", "users", {"username":username}, False)
    if user_record is None:
        return "This user does not exist", 404
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(newPwd.encode(), salt)
    dbclient.updateInDb("pollenisator", "users", {"username":username}, {"$set":{"hash":hashed}}, False)
    return "Success", 200

@permission("admin")
def listUsers() -> List[Dict[str, Any]]:
    """List all users in the database, excluding the hash and token.

    Returns:
        Dict[str, Any]: A dictionary containing the list of users.
    """
    dbclient = DBClient.getInstance()
    user_records = dbclient.aggregateFromDb("pollenisator", "users", [{"$project":{"hash":0, "token":0}}])
    return [user_record for user_record in user_records]

@permission("user")
def searchUsers(searchreq: str) -> List[str]:
    """
    Search for users in the database whose username matches the given search request.

    Args:
        searchreq (str): The search request, a string to match against usernames.

    Returns:
        List[str]: A list of usernames that match the search request.
    """
    dbclient = DBClient.getInstance()
    user_records = dbclient.findInDb("pollenisator", "users", {"username":{"$regex":f".*{searchreq}.*"}})
    return [user_record["username"] for user_record in user_records]

def login(body: Dict[str, str]) -> ErrorStatus:
    """
    Authenticate a user with the given username and password.

    Args:
        body (Dict[str, str]): A dictionary containing the username and password.
            "username" (str): The username of the user.
            "pwd" (str): The password of the user.

    Returns:
        ErrorStatus: The user's token if the authentication was successful, otherwise an error message and status code.
    """
    username = body.get("username", "")
    pwd = body.get("pwd", "")
    if username == "":
        return "username is required", 400
    elif pwd == "":
        return "pwd is required", 400
    dbclient = DBClient.getInstance()
    user_record = dbclient.findInDb("pollenisator", "users", {"username":username}, False, use_cache=False)
    if user_record is None:
        return "Authentication failure", 401
    if user_record["username"] == username:
        if bcrypt.checkpw(pwd.encode(), user_record["hash"]):
            return getTokenFor(username), 200
    return "Authentication failure", 401

def connectToPentest(pentest: str, _body: Dict[str, Any], **kwargs: Any) -> Union[Dict[str, Any], ErrorStatus]:
    """
    Connect to a pentest with the given details.

    Args:
        pentest (str): The UUID of the pentest to connect to.
        body (Dict[str, Any]): A dictionary containing additional parameters.
            "addDefaultCommands" (bool, optional): Whether to add default commands to the pentest.
        **kwargs (Any): Additional parameters, including the user token.

    Returns:
        Union[Dict[str, Any], ErrorStatus]: A dictionary containing the user's token and the pentest name if the connection was successful, otherwise an error message and status code.
    """
    username = kwargs["token_info"]["sub"]
    dbclient = DBClient.getInstance()
    if pentest not in dbclient.listPentestUuids():
        return "Pentest not found", 404
    pentest_rec = dbclient.findInDb("pollenisator", "pentests", {"uuid":pentest}, False)
    if pentest_rec is None:
        return "Pentest not found", 404
    pentest_name =  pentest_rec["nom"]
    testers = dbclient.getPentestUsers(pentest)
    token = kwargs.get("token_info", {})
    try:
        if dbclient.countInDb("pollenisator", "checkitems", {}) == 0:
            with open(getDefaultCheatsheetFile(), encoding="utf-8") as f:
                doImportCheatsheet(f.read(), username)
    except FileNotFoundError:
        pass

    if "admin" in token.get("scope", []):
        return {"token":getTokenFor(username, pentest, True), "pentest_name":pentest_name}
    else:
        owner = dbclient.getPentestOwner(pentest)
        testers.append(owner)
        if username not in testers:
            return "Forbidden", 403
        return {"token":getTokenFor(username, pentest, owner == username), "pentest_name":pentest_name}
