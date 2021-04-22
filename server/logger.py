import os
from datetime import datetime
def report(body):
    err = body.get("error", "")
    if err != "":
        logs_folder = os.path.join(os.path.dirname(
            os.path.realpath(__file__)), "../logs/clients/error.log")
        with open(logs_folder, "a") as f:
            f.write(datetime.now()+": "+err)