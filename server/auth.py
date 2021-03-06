#!/usr/bin/env python3
from core.Components.mongo import MongoCalendar
import bcrypt

from werkzeug.exceptions import Unauthorized
from server.permission import permission
from server.token import getTokenFor


@permission("admin")
def createUser(body):
    username = body.get("username", "")
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
    mongoInstance.insertInDb("pollenisator", "users", {"username":username, "hash":bcrypt.hashpw(pwd.encode(), salt), "scope":["user"]})
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
    return mongoInstance.updateInDb("pollenisator", "users", {"username":username}, {"$set":{"hash":hashed}}, False)


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
    return mongoInstance.updateInDb("pollenisator", "users", {"username":username}, {"$set":{"hash":hashed}}, False)

@permission("admin")
def listUsers():
    mongoInstance = MongoCalendar.getInstance()
    user_records = mongoInstance.aggregateFromDb("pollenisator", "users", [{"$project":{"hash":0, "token":0}}])
    return [user_record for user_record in user_records]
    
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
        return "Authentication failure", 404
    if user_record["username"] == username:
        if bcrypt.checkpw(pwd.encode(), user_record["hash"]):
            
            return getTokenFor(username)
    return "Authentication failure", 404

def connectToPentest(pentest, **kwargs):
    username = kwargs["token_info"]["sub"]
    mongoInstance = MongoCalendar.getInstance()
    if pentest not in mongoInstance.listCalendars():
        return "Pentest not found", 404
    testers = mongoInstance.getPentestUsers(pentest)
    token = kwargs.get("token_info", {})
    if "admin" in token.get("scope", []):
        return getTokenFor(username, pentest, True), 200
    else:
        owner = mongoInstance.getPentestOwner(pentest)
        testers.append(owner)
        if username not in testers:
            return "Forbidden", 403
        return getTokenFor(username, pentest, owner == username), 200
