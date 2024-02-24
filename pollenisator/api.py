"""
Start api server
"""
import eventlet
eventlet.monkey_patch()
# ENABLE debug mode early because evenlet monkey patch other libs
import os
from typing import Any
from flask_socketio import SocketIO

debug = bool(os.environ.get("FLASK_DEBUG", False))
if debug:
    async_mode = "threading" # Be aware thats sockets does not seems to work when debugging
else:
    
    async_mode = "eventlet"

import pollenisator.app_factory as app_factory
flask_app = app_factory.create_app(debug, async_mode)



@flask_app.route('/')
def home() -> str:
    """
    Returns a simple message to indicate that the API is working.

    Returns:
        str: A message indicating that the API is working.
    """
    return "Api working"

def main() -> None:
    """
    Create the app and run it
    """
    with flask_app.app_context():
        run(flask_app)

def run(flask_app: Any) -> SocketIO:
    """
    Starts the API server.
    """
    return app_factory.run(flask_app, debug)

# If we're running in stand alone mode, run the application
if __name__ == '__main__':
    main()
