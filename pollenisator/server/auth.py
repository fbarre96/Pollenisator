#!/usr/bin/env python3
from pollenisator.core.components.mongo import MongoCalendar
import bcrypt

from werkzeug.exceptions import Unauthorized
from pollenisator.server.permission import permission
from pollenisator.server.token import getTokenFor
from pollenisator.server.mongo import doImportCommands
from pollenisator.core.components.utils import getDefaultCommandsFile, getDefaultWorkerCommandsFile

@permission("admin")
def createUser(body):
    username = body.get("username", "")
    name = body.get("name", "")
    surname = body.get("surname", "")
    email = body.get("email", "")
    pwd = body.get("pwd", "")
    if username == "":
        return "username is required", 400
    elif pwd == "":
        return "pwd is required", 400
    mongoInstance = MongoCalendar.getInstance()
    user = mongoInstance.findInDb("pollenisator", "users", {"username":username}, False)
    if user is not None:
        return "A user with this username already exists", 403
    salt = bcrypt.gensalt()
    mongoInstance.insertInDb("pollenisator", "users", {"username":username, "hash":bcrypt.hashpw(pwd.encode(), salt), "name":name, "surname":surname, "email":email, "scope":["user"]})
    return "Successully created user"


@permission("admin")
def updateUserInfos(body):
    username = body.get("username", "")
    if username == "":
        return "username is required", 400
    mongoInstance = MongoCalendar.getInstance()
    user = mongoInstance.findInDb("pollenisator", "users", {"username":username}, False)
    if user is None:
        return "User not found", 404
    name = body.get("name", user.get("name",""))
    surname = body.get("surname", user.get("surname",""))
    email = body.get("email", user.get("email",""))
    mongoInstance.updateInDb("pollenisator", "users", {"username":username}, {"$set":{"name":name, "surname":surname, "email":email}})
    return "Successully created user"

@permission("admin")
def deleteUser(username):
    mongoInstance = MongoCalendar.getInstance()
    user = mongoInstance.findInDb("pollenisator", "users", {"username":username}, False)
    if user is not None:
        mongoInstance.deleteFromDb("pollenisator", "users", {"username":username}, False, False)
        return "User successfully deleted"
    else:
        return "User to delete not found", 404

@permission("user")
def changePassword(body, **kwargs):
    thisUser = kwargs["token_info"]["sub"]
    oldPwd = body.get("oldPwd", "")
    newPwd = body.get("newPwd", "")
    if oldPwd == "":
        return "oldPwd is required", 400
    elif newPwd == "":
        return "newPwd is required", 400
    username = thisUser
    mongoInstance = MongoCalendar.getInstance()
    user_record = mongoInstance.findInDb("pollenisator", "users", {"username":username}, False)
    if user_record is None:
        return "This user does not exist", 404
    salt = bcrypt.gensalt()
    if not bcrypt.checkpw(oldPwd.encode(), user_record["hash"]):
        return "The old password is incorrect", 403
    hashed = bcrypt.hashpw(newPwd.encode(), salt)
    mongoInstance.updateInDb("pollenisator", "users", {"username":username}, {"$set":{"hash":hashed}}, False)
    return True

@permission("admin")
def resetPassword(body):
    username = body.get("username", "")
    newPwd = body.get("newPwd", "")
    if username == "":
        return "username is required", 400
    elif newPwd == "":
        return "newPwd is required", 400
    mongoInstance = MongoCalendar.getInstance()
    user_record = mongoInstance.findInDb("pollenisator", "users", {"username":username}, False)
    if user_record is None:
        return "This user does not exist", 404
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(newPwd.encode(), salt)
    mongoInstance.updateInDb("pollenisator", "users", {"username":username}, {"$set":{"hash":hashed}}, False)
    return True

@permission("admin")
def listUsers():
    mongoInstance = MongoCalendar.getInstance()
    user_records = mongoInstance.aggregateFromDb("pollenisator", "users", [{"$project":{"hash":0, "token":0}}])
    return [user_record for user_record in user_records]
    
@permission("user")
def searchUsers(searchreq):
    mongoInstance = MongoCalendar.getInstance()
    user_records = mongoInstance.findInDb("pollenisator", "users", {"username":{"$regex":f".*{searchreq}.*"}})
    return [user_record["username"] for user_record in user_records]

def login(body):
    username = body.get("username", "")
    pwd = body.get("pwd", "")
    if username == "":
        return "username is required", 400
    elif pwd == "":
        return "pwd is required", 400
    mongoInstance = MongoCalendar.getInstance()
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(pwd.encode(), salt)
    user_record = mongoInstance.findInDb("pollenisator", "users", {"username":username}, False)
    if user_record is None:
        return "Authentication failure", 401
    if user_record["username"] == username:
        if bcrypt.checkpw(pwd.encode(), user_record["hash"]):
            
            return getTokenFor(username)
    return "Authentication failure", 401

def connectToPentest(pentest, body, **kwargs):
    username = kwargs["token_info"]["sub"]
    addDefaultCommands = body.get("addDefaultCommands", False)
    mongoInstance = MongoCalendar.getInstance()
    if pentest not in mongoInstance.listCalendarNames():
        return "Pentest not found", 404
    testers = mongoInstance.getPentestUsers(pentest)
    token = kwargs.get("token_info", {})
    try:
        if mongoInstance.countInDb("pollenisator", "commands", {}) == 0:
            with open(getDefaultWorkerCommandsFile()) as f:
                doImportCommands(f.read(), username)
        if addDefaultCommands:
            with open(getDefaultCommandsFile()) as f:
                doImportCommands(f.read(), username)
    except FileNotFoundError:
        pass
    if "admin" in token.get("scope", []):
        return getTokenFor(username, pentest, True), 200
    else:
        
        owner = mongoInstance.getPentestOwner(pentest)
        testers.append(owner)
        if username not in testers:
            return "Forbidden", 403
        return getTokenFor(username, pentest, owner == username), 200
