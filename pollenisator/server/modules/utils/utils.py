
import os
import shutil
from typing import Any, Dict, Tuple, Union
import pollenisator.core.components.utils as utils
from pollenisator.server.permission import permission
from pollenisator.core.components.logger_config import logger
import requests

ErrorStatus = Tuple[str, int]

def loadModuleConfig() -> Dict[str, Any]:
    """
    Load the server configuration from the config/utils.cfg file. If the file does not exist, it tries to create it from a sample config file.

    Returns:
        Dict[str, Any]: The json converted values of the module config file.

    Raises:
        SystemExit: If the config file or the sample config file does not exist, or if there is a permission error when trying to create the config file.
    """
    config_file = os.path.join(utils.getServerConfigFolder(), "utils.cfg")
    sample_config_file = os.path.join(utils.getMainDir(),"config/", "utils.cfg")
    if not os.path.isfile(config_file):
        if os.path.isfile(sample_config_file):
            try:
                shutil.copyfile(sample_config_file, config_file)
            except PermissionError:
                logger.error("Permission denied when trying to create a config file\n Please create the file %s (you can use the utils.cfg as a base)", os.path.normpath(config_file))
               
        else:
            logger.warning("Config file not found inside %s, please create one based on the provided utils.cfg inside the same directory.", os.path.normpath(config_file))
    return utils.loadCfg(config_file)

def do_completion(model, text, config) -> Union[ErrorStatus, Dict[str, Any]]:
    """
    Do text completion
    """
    response = requests.post(config["apiurl"],
                  json={ "model": model, "messages":[{"role":"user", "content":text}]},
                  headers={"Authorization": "Bearer "+config["apikey"]})
                  
    if response.status_code == 200:
        return response.json()
    else:
        return response.text, response.status_code

@permission("user")
def textcompletion_status(**kwargs):
    """
    Get text completion status
    """
    config = loadModuleConfig()
    status = {"status": "ready"}
    if not config:
        return {"status":"unavailable"}
    if config["apiurl"] == "":
        return {"status":"unavailable"}
    return status

@permission("user")
def textcompletion(body, **kwargs):
    """
    Get text completion
    """
    text = body.get("text", "")
    model = body.get("model", "")
    config = loadModuleConfig()
    if not config:
        return "No config file found", 500
    if not text:
        return "No text provided", 400
    if not model:
        return "No model provided", 400
    if model not in ["pollenisator-description", "pollenisator-remediation"]:
        return "Invalid model", 400
    return do_completion(model, text, config)
