import os
from datetime import datetime
from pollenisator.core.Components.Utils import getMainDir
def report(body):
    local_path = os.path.join(getMainDir(), "logs/clients/error.log")
    try:
        os.makedirs(local_path)
    except OSError:
        pass
    err = body.get("error", "")
    if err != "":
        with open(local_path, "a") as f:
            f.write(str(datetime.now())+": "+err)