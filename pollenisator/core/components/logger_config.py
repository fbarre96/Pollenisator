# /home/barre/Documents/Pollenisator/pollenisator/core/components/logger_config.py

import logging
import logging.handlers
import sys

# instead of basicConfig(filename=…) just configure everything by hand:
logger = logging.getLogger("pollenisator")
logger.setLevel(logging.DEBUG)

# This handler watches the on-disk file,
# and will reopen it if logrotate moves it out of the way.
debug_handler = logging.handlers.WatchedFileHandler("debug.log", encoding="utf-8", mode="a")
debug_handler.setLevel(logging.DEBUG)
debug_formatter = logging.Formatter(
    "%(asctime)s %(levelname)s %(name)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
debug_handler.setFormatter(debug_formatter)
logger.addHandler(debug_handler)

error_handler = logging.handlers.WatchedFileHandler("error.log", encoding="utf-8", mode="a")
error_handler.setLevel(logging.ERROR)
error_handler.setFormatter(debug_formatter)
logger.addHandler(error_handler)

# still log INFO+ to stdout
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setLevel(logging.DEBUG)
stream_handler.setFormatter(debug_formatter)
logger.addHandler(stream_handler)


def handle_exception(exc_type, exc_value, exc_traceback) -> None:
    if issubclass(exc_type, KeyboardInterrupt):
        # let Python do its default thing
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return

    logger.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))


sys.excepthook = handle_exception