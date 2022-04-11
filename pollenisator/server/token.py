from charset_normalizer import logging
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
    mod = False
    try:
        scopes = set(decode_token(user_record.get("token","")).get("scope", []))
    except:
        scopes = set()
    scopes = scopes.union(set(user_record.get("scope", [])))
    if pentest != "" and pentest not in scopes:
        scopes = set(user_record["scope"])
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
    return token

def generateNewToken(user_record, new_scopes):
    timestamp = _current_timestamp()
    payload = {
        "iat": int(timestamp),
        "exp": int(timestamp + JWT_LIFETIME_SECONDS),
        "sub": str(user_record["username"]),
        "scope": new_scopes,
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
        logging.info(f"Unauthorized, token is invalid : token ({token}) error ({e})")

        six.raise_from(Unauthorized, e)

def _current_timestamp():
    return datetime.datetime.now().timestamp()