"""
Module to handle the report generation and the search in the knowledge database
"""

import os
import re
import json
from datetime import datetime
from multiprocessing import Process, Manager
from queue import Queue
import threading
from typing import Any, Dict, List, Tuple, Union
from typing_extensions import TypedDict
from unidecode import unidecode
from flask import Response, send_file
from bson import ObjectId
import werkzeug
from pollenisator.core.models.defect import Defect
import pollenisator.core.reporting.wordexport as wordexport
import pollenisator.core.reporting.powerpointexport as powerpointexport
from pollenisator.server import settings
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.components.utils import getMainDir, getServerLocalFolder
from pollenisator.server.permission import permission
from pollenisator.core.components.logger_config import logger
from pollenisator.server.modules.filemanager.filemanager import listFiles
import os
import re
import requests
import shutil
from hashlib import md5


main_dir = getMainDir()
server_dir = getServerLocalFolder()
template_path = os.path.normpath(os.path.join(server_dir, "./Templates/"))
old_template_path = os.path.normpath(os.path.join(main_dir, "./Templates/"))
if(os.path.exists(template_path) is False) and os.path.exists(server_dir) is True:
    os.makedirs(template_path, exist_ok=True)
    shutil.copytree(old_template_path, template_path, dirs_exist_ok=True)
lang_translation = dict()

ErrorStatus = Tuple[str, int]
SearchResults = TypedDict("SearchResults", {"answers": List[Dict[str, Any]]})
SearchResultsPrevReports = TypedDict("SearchResultsPrevReports", {"existing_defects": List[Dict[str, Any]]})

def validate_lang(lang: str) -> bool:
    """
    Validate if the given language exists in the template path.

    Args:
        lang (str): The language to validate.

    Returns:
        bool: True if the language exists in the template path, False otherwise.
    """
    langs = [existing_lang for existing_lang in os.listdir(
        template_path) if os.path.isdir(os.path.join(template_path, existing_lang))]
    return lang in langs


@permission("user")
def getLangList() -> List[str]:
    """
    Get a list of all languages available in the template path.

    Returns:
        List[str]: A list of all languages available in the template path.
    """
    onlyfolders = [f for f in os.listdir(template_path) if not os.path.isfile(
        os.path.join(template_path, f))]
    return onlyfolders

@permission("user")
def getAllTemplateList() -> Union[ErrorStatus, Dict[str, List[str]]]:
    """Return all templates available in the template path."""
    langs = getLangList()
    templates = {}
    for lang in langs:
        templates[lang] = getTemplateList(lang)
    return templates

@permission("user")
def getTemplateList(lang: str) -> Union[ErrorStatus, List[str]]:
    """
    Get a list of all templates available for a given language.

    Args:
        lang (str): The language to get templates for.

    Returns:
       Union[ErrorStatus, List[str]]: A list of all templates available for the given language if successful, otherwise an error message and status code.
    """
    if not validate_lang(lang):
        return "There is no existing templates for this lang", 400
    lang = os.path.basename(lang)
    langs_path = os.path.join(template_path, lang)
    onlyfiles = [f for f in os.listdir(langs_path) if os.path.isfile(
        os.path.join(langs_path, f)) and f != "lang.json"]
    return onlyfiles

@permission("user")
def getTranslationsSettings(lang: str) -> Union[ErrorStatus, Dict[str, Any]]:
    """
    Get the translation settings for a given language.

    Args:
        lang (str): The language to get translation settings for.
    Returns:
        Union[ErrorStatus, Dict[str, Any]]: The translation settings for the given language if successful, otherwise an error message and status code.
    """
    if not validate_lang(lang):
        return "There is no existing templates for this lang", 400
    lang = os.path.basename(lang)
    if not validate_lang(lang):
        return "There is no existing templates for this lang", 400
    lang_file = os.path.join(template_path, lang, "lang.json")
    if not os.path.isfile(lang_file):
        return "There is no lang.json file for this lang", 400
    with open(lang_file, encoding="utf8") as f:
        return json.loads(f.read())

def create_lang(lang: str, body: Dict[str, Any]) -> str:
    """
    Create a new language folder and lang.json file with the given settings.

    Args:
        lang (str): The language to create.
        body (Dict[str, Any]): The translation settings to set.
    Returns:
        str: The path to the created lang.json file.
    """
    lang_folder = os.path.join(template_path, lang)
    os.makedirs(lang_folder, exist_ok=True)
    lang_file = os.path.join(lang_folder, "lang.json")
    with open(lang_file, "w", encoding="utf8") as f:
        f.write(json.dumps(body, indent=4, ensure_ascii=False))
    return lang_file

@permission("report_template_writer")
def setTranslationSettings(lang: str, body: Dict[str, Any]) -> ErrorStatus:
    """
    Set the translation settings for a given language.

    Args:
        lang (str): The language to set translation settings for.
        body (Dict[str, Any]): The translation settings to set.

    Returns:
        ErrorStatus: A success message if the translation settings were successfully set, otherwise an error message and status code.
    """
    lang = os.path.basename(lang)
    if not validate_lang(lang):
        new_lang = os.path.basename(lang).lower().strip()
        if re.match(r"^[a-z]{2}(-[A-Z]{2})?$", new_lang) is None:
            return "Invalid lang format, must be xx or xx-XX where x is a letter", 400
        lang = new_lang
    create_lang(lang, body)
    return "Success", 200

@permission("user")
def downloadTemplate(lang: str, templateName: str) -> Union[ErrorStatus, Response]:
    """
    Download a template for a given language.

    Args:
        lang (str): The language of the template.
        templateName (str): The name of the template to download.

    Returns:
        Union[ErrorStatus, Response]: The template to download if successful, otherwise an error message and status code.
    """
    fileName = os.path.basename(templateName)
    if not fileName.endswith(".pptx") and not fileName.endswith(".docx") and not fileName.endswith(".xlsx"):
        return "A template is either a pptx, xlsx or a docx document", 400
    lang = os.path.basename(lang)
    if not validate_lang(lang):
        return "There is no existing templates for this lang", 400
    template_to_download_path = os.path.join(template_path, lang+"/"+fileName)
    if not os.path.isfile(template_to_download_path):
        return "Template file not found", 404
    try:
        return send_file(template_to_download_path, attachment_filename=fileName) # python < 3.10
    except TypeError: # python3.10.6 breaks https://stackoverflow.com/questions/73276384/getting-an-error-attachment-filename-does-not-exist-in-my-docker-environment
        return send_file(template_to_download_path, download_name=fileName)


@permission("report_template_writer")
def uploadTemplate(upfile: werkzeug.datastructures.FileStorage, lang: str, overwrite: bool = False) -> ErrorStatus:
    """
    Upload a template for a given language.

    Args:
        upfile (werkzeug.datastructures.FileStorage): The template file to upload.
        lang (str): The language of the template.
        overwrite (bool):  allows to overwrite an existing template. Default to false to avoid accidental deletion.

    Returns:
        ErrorStatus: A success message if the template was successfully uploaded, otherwise an error message and status code.
    """
    if upfile is None:
        return "No file received", 400
    if upfile.filename is None:
        return "Empty filename received", 400
    fileName = upfile.filename.replace("/", "_")
    if not fileName.endswith(".pptx") and not fileName.endswith(".docx") and not fileName.endswith(".xlsx"):
        return "Invalid extension for template, must be pptx, xlsx or docx", 400
    new_lang = os.path.basename(lang).lower().strip()
    if re.match(r"^[a-z]{2}(-[A-Z]{2})?$", new_lang) is None:
        return "Invalid lang format, must be xx or xx-XX where x is a letter", 400
    if not validate_lang(new_lang):
        create_lang(new_lang, {})
    lang = new_lang
    folder_to_upload_path = os.path.join(template_path, lang+"/")
    
    template_to_upload_path = os.path.join(folder_to_upload_path, fileName)
    if os.path.isfile(template_to_upload_path) and not overwrite:
        return "Template already exists, use edition button to replace it", 400
    local_folder = getServerLocalFolder()
    backup_dir = os.path.join(local_folder, "backups")
    os.makedirs(backup_dir, exist_ok=True)
    if os.path.isfile(template_to_upload_path):
        with open(os.path.join(backup_dir, "backup_template_"+fileName+"_"+str(datetime.now().isoformat())+".bak"), "wb") as f:
            with open(template_to_upload_path, "rb") as original:
                f.write(original.read())

    with open(template_to_upload_path, "wb") as f:
        f.write(upfile.stream.read())
        return "Success", 200

@permission("report_template_writer")
def deleteTemplate(lang: str, body: Dict[str, Any]) -> ErrorStatus:
    """
    Delete a template for a given language.

    Args:
        lang (str): The language of the template.
        body:
            templateName (str): The name of the template to delete.

    Returns:
        ErrorStatus: A success message if the template was successfully deleted, otherwise an error message and status code.
    """
    templateName = body.get("templateName", "")
    if not (templateName and templateName.strip() != ""):
        return "Empty template name received", 400
    fileName = os.path.basename(templateName)
    if not fileName.endswith(".pptx") and not fileName.endswith(".docx") and not fileName.endswith(".xlsx"):
        return "Invalid extension for template, must be pptx, xlsx or docx", 400
    lang = os.path.basename(lang)
    if not validate_lang(lang):
        return "There is no existing templates for this lang", 400
    template_to_delete_path = os.path.join(template_path, lang+"/"+fileName)
    if not os.path.isfile(template_to_delete_path):
        return "Template file not found", 404
    if not os.path.commonprefix([template_path, template_to_delete_path]) == template_path:
        return "Invalid path", 400
    os.remove(template_to_delete_path)
    if not os.listdir(os.path.join(template_path, lang)):
        os.rmdir(os.path.join(template_path, lang))

    return "Success", 200

@permission("pentester")
def generateReport(pentest: str, body: Dict[str, Any]) -> Union[ErrorStatus, Response]:
    """
    Generate a report for a given pentest using a specified template.

    Args:
        pentest (str): The name of the pentest.
        body (Dict[str, Any]): A dictionary containing the template name, main redactor, language, and additional context for the report.

    Returns:
        Union[ErrorStatus, Response]: The generated report if successful, otherwise an error message and status code.
    """
    templateName = body.get("templateName", "")
    mainRedactor = body.get("mainRedactor", "")
    lang = body.get("lang", "en")
    additional_context = body.get("additional_context", {})
    if not templateName.endswith(".pptx") and not templateName.endswith(".docx") and not templateName.endswith(".xlsx"):
        return "Invalid extension for template, must be pptx, xlsx or docx", 400
    client_name = settings.find(pentest, "client_name")
    mission_name = settings.find(pentest, "mission_name")
    pentest_type = settings.find(pentest, "pentest_type")
    if client_name is None:
        client_name = ""
    else:
        client_name = client_name.get("value")
    if mission_name is None:
        mission_name = ""
    else:
        mission_name = mission_name.get("value")
    if pentest_type is None:
        pentest_type = "Web"
    else:
        pentest_type = str(pentest_type.get("value"))
    timestr = datetime.now().strftime("%Y%m")
    ext = os.path.splitext(templateName)[-1]
    basename = client_name.strip() + " - "+mission_name.strip()
    out_name = str(timestr)+" - "+basename
    templateName = os.path.basename(templateName)
    lang = os.path.basename(lang)
    if not validate_lang(lang):
        return "There is no existing templates for this lang", 400
    template_to_use_path = os.path.join(template_path, lang+"/", templateName)
    if not os.path.isfile(template_to_use_path):
        return "Template file not found", 404
    lang_file = os.path.join(template_path, lang+"/lang.json")
    global lang_translation
    with open(lang_file, encoding="utf8") as f:
        lang_translation = json.loads(f.read())
    try:
        context = craftContext(pentest, mainRedac=mainRedactor,
                            client=client_name.strip(), contract=mission_name.strip())
        context["pentest_type"] = pentest_type
        context.update(additional_context)
    

        #manager = Manager()
        result_queue = Queue()

        #return_dict = manager.dict()
        #p = Process(target=_generateDoc, args=(ext, context, template_to_use_path, out_name, lang_translation, return_dict))
        #p.start()
        thread = threading.Thread(target=_generateDoc, args=(ext, context, template_to_use_path, out_name, lang_translation, result_queue))
        thread.start()
        logger.info("Waiting for the report generation process to end...")
        thread.join(timeout=50)
        if thread.is_alive():
            logger.warning("Report generation is taking too long, terminating the process...")
            return "Report generation is taking too long and was terminated.", 500
        if result_queue.empty():
            return "An error occured while generating the report.", 500
        return_dict = result_queue.get()
        #p.join()
        logger.info("Report generation process ended.")
    except KeyError as e:
        return str(e), 400
    except Exception as e:
        logger.error(f"Error while generating the report: {e}")
        return "An error occured while generating the report.", 500
    if "res" not in return_dict:
        return "An error occured while generating the report.", 500
    if return_dict["res"] is True:
        logger.info("Report generated successfully")
        try:
            logger.info("Sending report file the old way "+out_name+ext)
            return send_file(return_dict["msg"], attachment_filename=out_name+ext)
        except TypeError as _e: # python3.10.6 breaks https://stackoverflow.com/questions/73276384/getting-an-error-attachment-filename-does-not-exist-in-my-docker-environment
            logger.info("Sending report file the new way "+out_name+ext)
            return send_file(return_dict["msg"], download_name=out_name+ext)
    else:
        return return_dict["msg"], 400

def _generateDoc(ext: str, context: Dict[str, Any], template_to_use_path: str, out_name: str, translation: Dict[str, Any], result_queue: Queue) -> None:
    """
    Generate a document report based on the given context and template.

    Args:
        ext (str): The extension of the output file.
        context (Dict[str, Any]): The context for the report.
        template_to_use_path (str): The path to the template to use.
        out_name (str): The name of the output file.
        translation (Dict[str, Any]): The translation dictionary to use.
        return_dict (Dict[str, Any]): A dictionary to store the result and message of the operation.
    """
    if ext == ".docx":
        res, msg = wordexport.createReport(
            context, template_to_use_path, out_name, translation=translation)
        logger.info("Report generation result: %s, message: %s", str(res), str(msg))
        #return_dict["res"] = res
        #return_dict["msg"] = msg
        result_queue.put({"res": res, "msg": msg})
        logger.info("Report generation finished, result: %s, message: %s", str(res), str(msg))
        return

    elif ext == ".pptx":
        res, msg = powerpointexport.createReport(
            context, template_to_use_path, out_name, translation=translation)
        # return_dict["res"] = res
        # return_dict["msg"] = msg
        result_queue.put({"res": res, "msg": msg})
    else:
        # return_dict["res"] = False
        # return_dict["msg"] = "Unknown template file extension"
        result_queue.put({"res": res, "msg": msg})

def searchDefectTemplates(terms: str, lang: str, perimeter: str, coll: str) -> List[Dict[str, Any]]:
    dbclient = DBClient.getInstance()
    res = dbclient.findInDb("pollenisator", coll, {}, True)
    ret = []
    if res is None:
        return ret
    for item in res:
        title = unidecode(item["title"]).lower()
        if terms not in title:
            continue
        if lang not in item.get("language", "").lower():
            continue
        if perimeter not in "\n".join(list(item.get("perimeter", []))).lower():
            continue
        ret.append(item)
    return ret

def searchDefectInPreviousReports(for_pentest: str, username:str, terms: str, lang: str, perimeter: str, coll: str) -> List[Dict[str, Any]]:
    dbclient = DBClient.getInstance()
    pentests = dbclient.listPentests(username)
    if pentests is None:
        return []
    ret = []
    for pentest in pentests:
        res = dbclient.findInDb(str(pentest.get("uuid","")), coll, {"target_id": None}, True)
        if res is None:
            continue
        for item in res:
            title = unidecode(item["title"]).lower()
            if terms not in title:
                continue
            if lang not in item.get("language", "").lower():
                continue
            if perimeter not in "\n".join(list(item.get("perimeter", []))).lower():
                continue
            item["from_pentest_name"] = pentest.get("nom","")
            item["from_pentest_uuid"] = str(pentest.get("uuid",""))
            item["pentest"] = for_pentest
            ret.append(item)
    return ret

@permission("user")
def search(body: Dict[str, str], **kwargs) -> Union[ErrorStatus, SearchResults]:
    """
    Search for defects or remarks in the database based on the given parameters.

    Args:
        body (Dict[str, str]): A dictionary containing the search parameters. 
            "type" (str): The type of item to search for (either "defect" or "remark").
            "terms" (str): The search terms.
            "language" (str): The language of the items to search for.
            "perimeter" (str): The perimeter of the items to search for.

    Returns:
        Union[ErrorStatus, SearchResults]: A dictionary containing any errors and the search results if successful, otherwise an error message and status code.
    """
    username = kwargs["token_info"]["sub"]
    if username == "" or username is None:
        return "Invalid token: no username found", 400
    defect_type = body.get("type", "")
    terms = unidecode(body.get("terms", "")).lower()
    lang = body.get("language", "").lower()
    perimeter = body.get("perimeter", "").lower()
    if defect_type == "remark":
        coll = "remarks"
    elif defect_type == "defect":
        coll = "defects"
    else:
        return "Invalid parameter: type must be either defect or remark.", 400
    answers: SearchResults = {"answers": []}
    answers["answers"] = searchDefectTemplates(terms, lang, perimeter, coll)
    return answers

@permission("pentester")
def searchInPreviousReports(pentest:str, body: Dict[str, str], **kwargs) -> Union[ErrorStatus, SearchResultsPrevReports]:
    """
    Search for defects or remarks in the database based on the given parameters.

    Args:
        body (Dict[str, str]): A dictionary containing the search parameters. 
            "type" (str): The type of item to search for (either "defect" or "remark").
            "terms" (str): The search terms.
            "language" (str): The language of the items to search for.
            "perimeter" (str): The perimeter of the items to search for.

    Returns:
        Union[ErrorStatus, SearchResults]: A dictionary containing any errors and the search results if successful, otherwise an error message and status code.
    """
    username = kwargs["token_info"]["sub"]
    if username == "" or username is None:
        return "Invalid token: no username found", 400
    defect_type = body.get("type", "")
    terms = unidecode(body.get("terms", "")).lower()
    lang = body.get("language", "").lower()
    perimeter = body.get("perimeter", "").lower()
    if defect_type == "remark":
        coll = "remarks"
    elif defect_type == "defect":
        coll = "defects"
    else:
        return "Invalid parameter: type must be either defect or remark.", 400
    existing_defects: SearchResultsPrevReports = {"existing_defects": []}
    existing_defects["existing_defects"] = searchDefectInPreviousReports(pentest, username, terms, lang, perimeter, coll)
    return existing_defects

def getDefectColor(risk: str) -> str:
    """
    Get the color associated with a defect risk level.

    Args:
        risk (str): The risk level of the defect.

    Returns:
        str: The color associated with the defect risk level.
    """
    return {"Critical":"263232","Major":"F7453C","Important":"EE8200", "Minor":"94C600"}.get(risk, "000000")

def replace_defect_links(description: str, defects: List[Dict[str, Any]]) -> str:
    """
    Replace defect links in a description with the defect titles.

    Args:
        description (str): The description to replace defect links in.
        defects (List[Dict[str, Any]]): The list of defects to search for.

    Returns:
        str: The description with the defect links replaced.
    """
    defects_titles = {defect.get("title","").strip():defect for defect in defects}
    for re_match in re.finditer(r"{{defect:([^}]+)}}", description):
        if re_match.group(1).strip() in defects_titles.keys():
            defect_id = defects_titles[re_match.group(1).strip()].get("index", 0)
            try:
                defect_id_str  = "D"+str(int(defect_id)+1)
                colours = "**<color:"+str(getDefectColor(defects_titles[re_match.group(1).strip()].get("risk","")))+">"+str(defect_id_str)+"</color>**"
                description = description.replace(re_match.group(0), colours)
            except ValueError:
                pass
        else:
            raise KeyError(f"Defect {re_match.group(1)} is referenced and was not found")
    return description

def add_global_infos_in_context(pentest: str, context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Add global information about the pentest to the context.

    Args:
        pentest (str): The name of the pentest.
        context (Dict[str, Any]): The context to add the global information to.

    Returns:
        Dict[str, Any]: The context with the added global information.
    """
    context["pentest"] = pentest
    date = datetime.now()
    context["year"] = date.strftime("%Y")
    context["month"] = date.strftime("%B").lower()
    context["colors"] = {
        "fix": {
            "Easy": "00B0F0",
            "Moderate": "0070C0",
            "Mean": "0070C0",
            "Hard": "002060",
            "Quick Win": "00B0F0",
            "Weak": "00B0F0",
            "Strong": "002060",
        }
    }
    return context

def add_scopes_in_context(pentest: str, context: Dict[str, Any]) -> Dict[str, Any]:
    dbclient = DBClient.getInstance()
    scopes_list = [scope for scope in dbclient.findInDb(pentest, "scopes", {}, True)]
    context["scopes"] = scopes_list
    return context

def craftContext(pentest: str, **kwargs: Any) -> Dict[str, Any]:
    """
    Craft the context for a report based on the given pentest and additional parameters.

    Args:
        pentest (str): The name of the pentest.
        **kwargs (Any): Additional parameters to include in the context.

    Returns:
        Dict[str, Any]: The crafted context for the report.
    """
    context = {}
    for k, v in kwargs.items():
        context[k] = v
    context = add_global_infos_in_context(pentest, context)
    context = add_remarks_in_context(pentest, context)
    context = add_scopes_in_context(pentest, context)
    context = add_pentesters_in_context(pentest, context)
    context = add_ports_in_context(pentest, context)
    context = add_defects_in_context(pentest, context)
    context = add_additional_sections_in_context(pentest, context)
    return context

def add_additional_sections_in_context(pentest: str, context: Dict[str, Any]) -> Dict[str, Any]:
    dbclient = DBClient.getInstance()
    try:
        additional_sections = dbclient.findInDb("pollenisator", "additionalreportsections", {}, True)
        if additional_sections is None:
            additional_sections = []
        lookup = {}
        for additional_section in additional_sections:
            lookup[str(additional_section["_id"])] = additional_section.get("title", "")
        pentest_sections = dbclient.findInDb(pentest, "additionalreportsections", {}, True)
        if pentest_sections is None:
            pentest_sections = []
        for pentest_section in pentest_sections:
            if "_id" in pentest_section:
                del pentest_section["_id"]
            title = lookup.get(str(pentest_section.get("section_id", "")), "")
            if title != "":
                context[title] = context.get(title, {}) | pentest_section
    except Exception as e:
        logger.error(f"Error while adding additional sections to the report: {e}")
    return context

def add_defects_in_context(pentest:str, context: Dict[str, Any]) -> Dict[str, Any]:
    dbclient = DBClient.getInstance()
    completed_defects = []
    completed_fixes = []
    defect_id = 1
    defects = Defect.getGlobalDefects(pentest)
    for defect in defects:
        defect_completed = defect
        defect_completed["id"] = str(defect_id)
        proof_path = getProofPath(pentest, ObjectId(defect_completed["_id"]))
        global_proofs = []
        for pr in defect_completed["proofs"]:
            global_proofs.append(os.path.join(proof_path, os.path.basename(pr)))
        defect_completed["proofs"] = global_proofs
        defect_completed["description"] =  defect_completed["description"].replace("\r","")
        defect_completed["description"] = re.sub(r"(?<!\n\n)(!\[.*\]\((.*?)\))", r"\n\1", defect_completed["description"])
        defect_completed["description"] = re.sub(r"(!\[.*\]\((.*?)\))(?!\n\n)", r"\1\n", defect_completed["description"])
        try:
            defect_completed["description"] = replace_defect_links(defect_completed["description"], defects)
        except KeyError as e:
            logger.error(f"Error while replacing defect links in description: {e}")
            raise KeyError(str(e)+" in defect "+str(defect_completed.get("title", "")))
        defect_completed["description_paragraphs"] = defect_completed["description"].replace("\r","").split("\n")
        fix_id = 1
        if len(defect_completed["fixes"]) > 1:
            for fix in defect_completed["fixes"]:
                fix["id"] = str(defect_id)+"."+str(fix_id)
                fix_id += 1
        elif len(defect_completed["fixes"]) == 1:
            defect_completed["fixes"][0]["id"] = str(defect_id)
        else:
            logger.warning("Warning: defect in base with no fix")
        for i, fix in enumerate(defect_completed["fixes"]):
            defect_completed["fixes"][i]["description"] =  fix["description"].replace("\r","")
            defect_completed["fixes"][i]["description"] = replace_defect_links(defect_completed["fixes"][i]["description"], defects)
            defect_completed["fixes"][i]["description_paragraphs"] = fix["description"].replace("\r","").split("\n")
        completed_fixes += defect_completed["fixes"]
        defect_id += 1
        assignedDefects = dbclient.findInDb(pentest, "defects", {"global_defect":ObjectId(defect_completed["_id"])}, True)
        defect_completed["instances"] = []
        for assignedDefect in assignedDefects:
            local_proofs = []
            proof_path = getProofPath(pentest, ObjectId(assignedDefect["_id"]))
            for pr in assignedDefect.get("proofs", []):
                local_proofs.append(os.path.join(proof_path, os.path.basename(pr)))
            
            notes_paragraphs = assignedDefect.get("notes", "").replace("\r", "").split("\n")
            assignedDefect["proofs"] = local_proofs
            assignedDefect["notes"] = assignedDefect.get("notes", "").replace("\r", "")
            assignedDefect["notes_paragraphs"] = notes_paragraphs
            defect_completed["instances"].append(assignedDefect)
        completed_defects.append(defect_completed)
    context["defects"] = completed_defects
    context["fixes"] = completed_fixes
    return context

def add_ports_in_context(pentest:str , context: Dict[str, Any]) -> Dict[str, Any]:
    dbclient = DBClient.getInstance()
    ports = dbclient.findInDb(pentest, "ports", {}, True)
    ports = [port for port in ports]
    ports.sort(key=lambda x: (x["ip"],int(x["port"])))
    context["ports"] = ports
    return context

def add_pentesters_in_context(pentest: str, context: Dict[str, Any]) -> Dict[str, Any]:
    dbclient = DBClient.getInstance()
    pentesters = dbclient.getPentestUsers(pentest)
    context["pentesters"] = []
    for pentesterName in pentesters:
        p = dbclient.getUserRecordFromUsername(pentesterName)
        if p is not None:
            context["pentesters"].append(p)
    owner = dbclient.getPentestOwner(pentest)
    p = dbclient.getUserRecordFromUsername(owner)
    context["owner"] = p if p is not None else None
    return context

def add_remarks_in_context(pentest: str, context: Dict[str, Any]) -> Dict[str, Any]:
    dbclient = DBClient.getInstance()
    context["positive_remarks"] = []
    context["negative_remarks"] = []
    context["neutral_remarks"] = []
    remarks = dbclient.findInDb(pentest, "remarks", {}, True)
    for remark in remarks:
        if remark["type"].lower() == "positive":
            context["positive_remarks"].append(remark.get("description", remark.get("title", "")))
        elif remark["type"].lower() == "negative":
            context["negative_remarks"].append(remark.get("description", remark.get("title", "")))
        elif remark["type"].lower() == "neutral":
            context["neutral_remarks"].append(remark.get("description", remark.get("title", "")))
    return context

def getProofPath(pentest: str, defect_iid: ObjectId) -> str:
    """
    Get the local path to the proof of a defect in a pentest.

    Args:
        pentest (str): The name of the pentest.
        defect_iid (ObjectId): The id of the defect.

    Returns:
        str: The local path to the proof of the defect.
    """
    local_path = os.path.join(getMainDir(), "files")
    return os.path.join(local_path, pentest, "proof", str(defect_iid))

