import os
from datetime import datetime
from pollenisator.core.components.utils import getMainDir

def report(body):
    local_path = os.path.join(getMainDir(), "logs/clients/")
    try:
        os.makedirs(local_path)
    except OSError:
        pass
    local_path = os.path.join(local_path, "error.log")
    err = body.get("error", "")
    if err != "":
        with open(local_path, "a") as f:
            f.write(str(datetime.now())+": "+err)