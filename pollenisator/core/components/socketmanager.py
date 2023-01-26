import os
from pollenisator.core.components.logger_config import logger
from flask_socketio import SocketIO

class SocketManager:
    """
    Centralize all direct contacts with the socketio obj.
    """
    __instances = {}

    @staticmethod
    def getInstance():
        """ Singleton Static access method.
        """
        pid = os.getpid()  # HACK : One mongo per process.
        instance = SocketManager.__instances.get(pid, None)
        if instance is None:
            SocketManager()
        return SocketManager.__instances[pid]

    def __init__(self):
        """ DO NOT USE THIS CONSTRUCTOR IT IS A
        Virtually private constructor.  Use MongoCalendar.getInstance()
        Args:
           
        Raises:
            Exception if it is instanciated.
        """
        pid = os.getpid()  # HACK : One mongo per process.
        if SocketManager.__instances.get(pid, None) is not None:
            raise Exception("This class is a singleton!")
        else:
            self.socketio = SocketIO(logger=logger, engineio_logger=logger, cors_allowed_origins="*")
            SocketManager.__instances[pid] = self

