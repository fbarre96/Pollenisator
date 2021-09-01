from jose import JWTError, jwt
from pollenisator.core.Components.mongo import MongoCalendar
import datetime
import datetime
import uuid
from werkzeug.exceptions import Unauthorized
import six

JWT_SECRET = str(uuid.uuid4())
JWT_LIFETIME_SECONDS = 3600*8
JWT_ALGORITHM = 'HS256'

def getTokenFor(username, pentest="", owner=False):
    mongoinstance = MongoCalendar.getInstance()
    user_record = mongoinstance.findInDb("pollenisator", "users", {"username":username}, False)
    if user_record is None:
        return ""
    if pentest != "" and pentest not in user_record.get("scope", []):
        user_record["scope"] = user_record.get("scope", []) + [pentest]
        if owner:
            user_record["scope"].append("owner")
        user_record["scope"].append("pentester")
    if "user" not in user_record["scope"]:
        user_record["scope"].append("user")
    token = generateNewToken(user_record)
    return token

def generateNewToken(user_record):
    timestamp = _current_timestamp()
    payload = {
        "iat": int(timestamp),
        "exp": int(timestamp + JWT_LIFETIME_SECONDS),
        "sub": str(user_record["username"]),
        "scope": user_record["scope"],
    }
    jwt_encoded = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    mongoInstance = MongoCalendar.getInstance()
    mongoInstance.updateInDb("pollenisator", "users", {"_id":user_record["_id"]}, {"$set":{"token":jwt_encoded}})
    return jwt_encoded

def verifyToken(access_token):
    try:
        jwt_decoded = jwt.decode(access_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError as e:
        return False

    return checkTokenValidity(jwt_decoded)

def checkTokenValidity(jwt_decoded):
    mongoInstance = MongoCalendar.getInstance()
    access_token = encode_token(jwt_decoded)
    user = mongoInstance.findInDb("pollenisator", "users", {"token":access_token}, False)
    if user is not None:
        exp_timestamp = jwt_decoded.get("exp", datetime.datetime.now().timestamp())
        if datetime.datetime.now().timestamp() > exp_timestamp:
            return False
        return True
    return False

def encode_token(token_info):
    return jwt.encode(token_info, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_token(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError as e:
        six.raise_from(Unauthorized, e)

def _current_timestamp():
    return datetime.datetime.now().timestamp()