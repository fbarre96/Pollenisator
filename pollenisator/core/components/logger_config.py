
import logging
import sys
logging.basicConfig(filename='debug.log', encoding='utf-8', level=logging.DEBUG)
file_handler_error = logging.FileHandler('error.log', mode='w')
file_handler_error.setLevel(logging.ERROR)
logger = logging.getLogger(__name__)
handler = logging.StreamHandler(stream=sys.stdout)
logger.addHandler(handler)
logger.addHandler(file_handler_error)

def handle_exception(exc_type, exc_value, exc_traceback):
    logger.error("Exception", exc_info=(exc_type, exc_value, exc_traceback))
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return

    logger.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))

sys.excepthook = handle_exception