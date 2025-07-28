"""Singleton pattern for the socketio object."""

import os
from typing import Dict
from flask_socketio import SocketIO
from pollenisator.core.components.logger_config import logger

class SocketManager:
    """
    Centralize all direct contacts with the socketio obj.
    """
    __instances: Dict[int, "SocketManager"] = {} # Singleton instances

    @staticmethod
    def getInstance() -> 'SocketManager':
        """
        Singleton Static access method. One instance per process.

        Returns:
            SocketManager: The singleton instance of SocketManager for the current process.
        """
        pid = os.getpid()  # HACK : One mongo per process.
        instance = SocketManager.__instances.get(pid, None)
        if instance is None:
            SocketManager()
        return SocketManager.__instances[pid]

    def __init__(self) -> None:
        """
        DO NOT USE THIS CONSTRUCTOR IT IS A
        Virtually private constructor. Use SocketManager.getInstance()

        Raises:
            Exception: If an instance already exists for the current process.
        """
        pid = os.getpid()  # HACK : One mongo per process.
        if SocketManager.__instances.get(pid, None) is not None:
            raise TypeError("This class is a singleton!")
        else:
            self.socketio = SocketIO(logger=logger, engineio_logger=logger, cors_allowed_origins="*", cors_credentials=True)
            SocketManager.__instances[pid] = self
