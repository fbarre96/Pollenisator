# ENABLE debug mode early because evenlet monkey patch other libs
import os
import uuid

debug = os.environ.get("FLASK_DEBUG", False)
if debug:
    async_mode = "threading" # Be aware thats sockets does not seems to work when debugging
else:
    import eventlet
    eventlet.monkey_patch()
    async_mode = "eventlet"

import pollenisator.app_factory as app_factory
flask_app = app_factory.create_app(debug, async_mode)



@flask_app.route('/')
def home():
    """Returns a simple message to indicate that the API is working.
    """
    return "Api working"

def main():
    """Create the app and run it
    """
    with flask_app.app_context():
        run(flask_app)
    
def run(flask_app):
    """Starts the API server.
    """
    return app_factory.run(flask_app, debug)
    

# If we're running in stand alone mode, run the application
if __name__ == '__main__':
    main()


