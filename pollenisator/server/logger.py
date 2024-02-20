"""
logger error reporting for /issue.
"""

from pollenisator.core.components.logger_config import logger

def report(body):
    """
    Report the error to the log file.
    """
    err = body.get("error", "")
    if err != "":
        logger.error("ISSUE : Error reported by user: %s", str(err))
