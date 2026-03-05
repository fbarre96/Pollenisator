from typing import Any
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.components.logger_config import logger
import inspect

from pollenisator.server.token import checkTokenValidity
# permission decorator

all_permissions = ["admin", "user", "owner", "pentester", "template_writer", "worker", "report_template_writer", "write_defect_script"]


def checkPentestPermission(token_info: dict[str, Any], pentest: str, check_owner: bool) -> bool:
    """
    Check if the user has permission to access the specified pentest.

    Args:
        token_info (Dict[str, Any]): The token information containing user details and scopes.
        pentest (str): The name of the pentest to check permissions for.
        check_owner (bool): If True, check if the user is the owner of the pentest.

    Returns:
        bool: True if the user has permission, False otherwise.
    """
    if "admin" in token_info.get("scope", []):
        return True
    if "user" not in token_info.get("scope", []):
        return False
    user = token_info.get("sub", "")
    if user == "":
        logger.debug("Forbidden : user is not defined in token_info")
        return False
    dbclient = DBClient.getInstance()
    result = dbclient.findInDb("pollenisator", "pentests", {"uuid": pentest}, False)
    if result is None:
        return False
    if result.get("owner", "") == user:
        return True
    if check_owner:
        logger.debug(f"Forbidden : {user} is not the owner of {pentest}")
        return False
    if user in result.get("pentesters", []):
        return True
    return False


def permission(*dec_args, **deckwargs):
    def _permission(function):
        def wrapper(*args, **kwargs):
            token_info = kwargs.get("token_info", None)
            if token_info is None: # permission called from already checked function, assume authorization
                result = function(*args, **kwargs)
                return result
            scope = dec_args[0]
            arg_name = dec_args[1] if len(dec_args) == 2 else "pentest"
            #Check token_info and user kwargs supplied to the function by connexion specifying a security
            args_spec = inspect.getfullargspec(function)
            user = kwargs.get("user", "")
            if user == "":
                return "Unauthorized", 401
            if "api_key_id" not in token_info:
                if not checkTokenValidity(token_info, []):
                    return "Unauthorized", 401
            else:
                # already verified api key
                pass
            token_scope = token_info.get("scope", []) 
            if "admin" in token_scope:
                for perm in all_permissions:
                    if perm not in token_scope:
                        token_scope.append(perm)
                token_info["scope"] = token_scope
            # Check scope inside token
            if scope not in token_scope and scope != "pentester" and scope != "owner":
                logger.debug(f"FORBIDDEN : {scope} not in {token_info}")
                return f"Forbidden : {scope} is required", 403
            if (scope == "pentester" or scope == "owner") and "worker" not in token_scope:
                if "." in arg_name:
                    dict_name, dict_key = arg_name.split(".")
                    dict_obj = kwargs.get(dict_name)
                    arg_value = dict_obj[dict_key]
                else:
                    arg_value = kwargs.get(arg_name)
                    if arg_value is None and arg_name in args_spec.args:
                        arg_value_i = args_spec.args.index(arg_name)
                        arg_value = args[arg_value_i]
                if not checkPentestPermission(token_info, arg_value, scope == "owner"):
                    return f"Forbidden : you are not allowed to access {arg_value}", 403
                
            if scope == "worker":
                if arg_name == "pentest":
                    arg_name = "name"
                ind = args_spec.args.index(arg_name)
                arg_value = args[ind]
                if arg_value not in token_scope:
                    logger.debug(f"{arg_value} for workers is not in the token scope {token_info}")
                    return f"Forbidden : scope required worker and name {arg_value}", 403
            
            args_recalc = recalculate_arguments(args, kwargs, args_spec)
            expect_kw = args_spec.varkw is not None
            if expect_kw:
                result = function(*args_recalc, **kwargs)
            else:
                result = function(*args_recalc)
            return result

        def recalculate_arguments(args, kwargs, args_spec):
            args_recalc = []
            for expected_arg_names in args_spec.args:
                value = kwargs.get(expected_arg_names, None)
                try:
                    del kwargs[expected_arg_names]
                except KeyError:
                    try:
                        if expected_arg_names in args_spec.args:
                            value_i = args_spec.args.index(expected_arg_names)
                            value = args[value_i]
                    except IndexError:
                        pass

                args_recalc.append(value)
            return args_recalc
        
        return wrapper
    return _permission
