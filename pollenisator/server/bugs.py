"""
logger error reporting for /issue.
"""
import time 
from typing import Any, Dict, List, Union
from pollenisator.core.components.logger_config import logger
from pollenisator.server.permission import permission
import secrets
from pollenisator.core.components.utils import getServerLocalFolder
import os
import json

@permission("user")
def feedback(body: Dict[str, Any], **kwargs) -> bool:
    """
    Report the feedback to the log file. The body should contain:
    - description: str
    - title: str
    - category: str
    - infos: Dict[str, Any]
    """
    user = kwargs.get("token_info", "unknown").get("sub", "unknown")
    desc = body.get("description", "")
    title = body.get("title", "")
    category = body.get("category", "general")
    infos = body.get("infos", {})
    infos["timestamp"] = time.time()
    local_dir = getServerLocalFolder()
    reported_issues_dir = os.path.join(local_dir, "reported_issues")
    os.makedirs(reported_issues_dir, exist_ok=True)
    #generate filename with timestamp
    secrets_token = secrets.token_hex(16)
    filename = f"{int(time.time())}_{secrets_token}.log"
    filepath = os.path.join(reported_issues_dir, filename)
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump({
                "user": user,
                "title": title,
                "description": desc,
                "category": category,
                "infos": infos
            }, f)
    except Exception as e:
        logger.error(f"Failed to save reported issue: {e}")
        return False

    return True
