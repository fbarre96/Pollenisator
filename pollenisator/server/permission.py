import logging
import connexion
import inspect
from copy import deepcopy
from pollenisator.server.token import checkTokenValidity
# permission decorator

def permission(*dec_args, **dec_kwargs):
    def _permission(function):
        def wrapper(*args, **kwargs):
            scope = dec_args[0]
            arg_name = dec_args[1] if len(dec_args) == 2 else "pentest"
            #Check token_info and user kwargs supplied to the function by connexion specifying a security
            args_spec = inspect.getfullargspec(function)
            user = kwargs.get("user", "")
            token_info = kwargs.get("token_info", None)
            if token_info is None: # permission called from already checked function, assume authorization
                result = function(*args, **kwargs)
                return result
            if user == "":
                return "Unauthorized", 401
            if not checkTokenValidity(token_info):
                return "Unauthorized", 401
            
            token_scope = token_info.get("scope", []) 
            if "admin" in token_scope and "user" not in token_scope:
                token_scope.append("user")
                token_info["scope"] = token_scope
            # Check scope inside token
            if scope not in token_scope:
                logging.debug(f"FORBIDDEN : {scope} not in {token_info}")
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
                if arg_value not in token_scope:
                    if "admin" not in token_scope:
                        logging.debug(f"{arg_value} is not in the token scope {token_info}")
                        return f"Forbidden : you do not have access to {arg_value}", 403
            if scope == "worker":
                if arg_name == "pentest":
                    arg_name = "name"
                ind = args_spec.args.index(arg_name)
                arg_value = args[ind]
                if arg_value not in token_scope:
                    logging.debug(f"{arg_value} for workers is not in the token scope {token_info}")
                    return f"Forbidden : scope required worker and name {arg_value}", 403
            
            args_recalc = []
            for expected_arg_names in args_spec.args:
                value = kwargs.get(expected_arg_names, None)
                try:
                    del kwargs[expected_arg_names]
                except KeyError:
                    if expected_arg_names in args_spec.args:
                        value_i = args_spec.args.index(expected_arg_names)
                        value = args[value_i]
                args_recalc.append(value)
            expect_kw = args_spec.varkw is not None
            if expect_kw:
                logging.debug("Calling function with args "+str(args_recalc)+" , "+str(kwargs))
                result = function(*args_recalc, **kwargs)
            else:
                logging.debug("Calling function with args "+str(args_recalc))
                result = function(*args_recalc)
            return result
            
        return wrapper
    return _permission