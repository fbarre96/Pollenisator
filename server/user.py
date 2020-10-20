import json
from core.Components.mongo import MongoCalendar

mongoInstance = MongoCalendar.getInstance()

def login(login):

    sessionid = mongoInstance.loginUser(login["username"])
    if sessionid != "":
        return sessionid
    else:
        return 403