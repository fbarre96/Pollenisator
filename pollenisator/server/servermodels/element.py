"""
Handle generic request common to all elements
"""
from typing import List, Set
from pollenisator.server.permission import permission

from pollenisator.core.models.element import REGISTRY

@permission("user")
def getCommandVariables() -> List[str]:
    """
    Return the list of command variables for all classes. The command variables are extracted from the registry of class names.

    Returns:
        List[str]: A sorted list of unique command variables as strings.
    """
    ret: Set[str] = set()
    for _, class_type in REGISTRY.items():
        ret = ret.union(set(class_type.getCommandVariables()))
    return sorted(list(ret))

@permission("user")
def getTriggerLevels() -> List[str]:
    """
    Return the list of trigger levels of this object. The trigger levels are extracted from the registry of class names.

    Returns:
        List[str]: A sorted list of unique trigger levels as strings.
    """
    ret: Set[str] = set()
    for _, class_type in REGISTRY.items():
        ret = ret.union(set(class_type.getTriggers()))
    return sorted(list(ret))
