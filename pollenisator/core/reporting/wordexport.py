from typing import Any, Dict, Tuple, Union
from pollenisator.core.components.logger_config import logger
import os
from docxtpl import DocxTemplate
from docxtpl import InlineImage
import jinja2
from markdowntodocx.markdownconverter import convertMarkdownInFile
import re
from docx.shared import Cm
import base64
from pollenisator.core.components.utils import getMainDir
from pollenisator.server.modules.filemanager.filemanager import listFiles
translation: Dict[str, str] = {}


def b64encode(string):
    return base64.b64encode(string.encode()).decode()

def translate(w):
    if isinstance(w, list):
        trads = []
        for x in w:
            trads.append(translation.get(x, x))
        return trads
    return translation.get(w, w)

def getInitials(words):
    initials = []
    if isinstance(words,str):
        words = words.split(",")
    for word in words:
        try:
            word_str = "".join([x[0] for x in word.split(" ")]) # Active Directory -> AD and Base -> B
        except IndexError:
            word_str = ""
        initials.append(word_str)
    return ", ".join(initials)

def regex_findall(string, pattern):
    matches = re.findall(pattern, string)
    return matches

def debug(string):
    print(string)
    return string


def createReport(context: Dict[str, Any], template: str, out_name: str, **kwargs: Any) -> Union[Tuple[bool, str], Tuple[bool, str]]:
    """
    Create a report based on a template and a context.

    Args:
        context (Dict[str, Any]): The context for the report, including defects and their proofs.
        template (str): The path to the template file.
        out_name (str): The name of the output file.
        **kwargs (Any): Additional parameters, including the translation.

    Returns:
        Union[Tuple[bool, str], Tuple[bool, str]]: A tuple containing a boolean indicating whether the operation was successful, and a string containing the path to the generated report or an error message.
    """
    global translation
    translation = kwargs.get("translation" ,{})
    doc = DocxTemplate(template)
    jinja_env = jinja2.Environment(autoescape=True)
    jinja_env.filters['translate'] = translate
    jinja_env.filters['b64encode'] = b64encode
    jinja_env.filters['getInitials'] = getInitials
    jinja_env.filters['regex_findall'] = regex_findall
    jinja_env.filters['debug'] = debug
    # TODO : MAYBE This code could removed now that the file:/// is supported in markwdown (see replaceUnassingedFIleImages)
    context["proof_by_names"] = {}
    for defect in context["defects"]:
        proofs = defect.get("proofs", [])
        proofs_by_name = {}
        for proof in proofs:
            proofs_by_name[os.path.basename(proof)] = proof
        for i, para in enumerate(defect.get("description_paragraphs", [])):
            re_matches = re.finditer(r"!\[(.*)\]\(.*\)", para.strip())
            for re_match in re_matches:
                if re_match.group(1).strip() in proofs_by_name:
                    proof = proofs_by_name[re_match.group(1).strip()]
                    if not os.path.isfile(proof):
                        return False, f"Proof file not found : {str(re_match.group(1).strip())} for defect {str(defect.get('title', ''))}"
                    defect["description_paragraphs"][i] = InlineImage(doc, proof, width=Cm(17))
                    context["proof_by_names"][os.path.basename(proof)] = defect["description_paragraphs"][i] 
        for instance in defect.get("instances", []):
            for i,proof in enumerate(instance.get("proofs", [])):
                instance["proofs"][i] = InlineImage(doc, proof)
    # TODO : END
    recursiveEdits(context, context["pentest"])
    
    try:
        doc.render(context, jinja_env)
    except jinja2.exceptions.TemplateSyntaxError as e:
        return False, "Error in template syntax : "+str(e)
    dir_path = os.path.dirname(os.path.realpath(__file__))
    out_path = os.path.join(dir_path, "../../exports/", out_name+".docx")
    doc.save(out_path)
    doc.save("/tmp/"+out_name+".docx")
    logger.info("Converting Markdown of %s", str(out_path))
    result, msg = convertMarkdownInFile(out_path, out_path, {"Header":"Sous-défaut",
        "Header1":"Sous-défaut",
        "Header2":"Sous-défaut",
        "Header3":"Sous-défaut",
        "Header4":"Sous-défaut",
        "Header5":"Sous-défaut",
        "Header6":"Sous-défaut",
        "Table":"StyleTableau" })
    if not result:
        return False, "Error in Markdown conversion : "+str(msg)
    logger.info("Generated report at %s", str(out_path))
    return True, out_path


regex_replace_lonely_lf = re.compile(r"(?<!\n)\n(?!\n)")
regex_replace_images = re.compile(r"(?<!\n\n)(!\[.*\]\((.*?)\))")
regex_replace_images_no_newline = re.compile(r"(!\[.*\]\((.*?)\))(?!\n\n)")

def recursiveEdits(context: dict, pentest: str) -> None:
    """
    Recursively iterate over the context dictionary (up to 10 levels deep)
    and download markdown images, replacing remote URLs with the local file path.
    also replaces lonely newlines with double newlines.

    Args:
        context (dict): The context dictionary to process.
        pentest (str): The name of the pentest to build the local storage path.
    """
    pattern = r"(!\[.*\]\((.*?)\))"
    files = listFiles(pentest, "unassigned", "file")
    if files is None or not isinstance(files, list):
        files = []
    pollenisator_files = listFiles("pollenisator", "unassigned", "file")
    if pollenisator_files is None or not isinstance(pollenisator_files, list):
        pollenisator_files = []
    def _recursive_process(obj, depth: int):
        if depth > 10:
            return obj

        if isinstance(obj, dict):
            for key, value in obj.items():
                obj[key] = _recursive_process(value, depth + 1)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                obj[i] = _recursive_process(item, depth + 1)
        elif isinstance(obj, str):
            # replace lonely \n with \n\n
            obj = regex_replace_lonely_lf.sub("\n\n", obj)
          
            # Regex to find markdown images with http/https URLs
            obj = regex_replace_images.sub(r"\n\1", obj)
            obj = regex_replace_images_no_newline.sub(r"\1\n", obj)
            def repl(match):
                alt_text = match.group(1)
                url = match.group(2)
                if url in files:
                    pentest_base_dir = os.path.normpath(os.path.join(getMainDir(), "files", pentest, "file", "unassigned"))
                    pentest_path = os.path.normpath(os.path.join(pentest_base_dir, os.path.basename(url)))
                    if pentest_path.startswith(pentest_base_dir):
                        if os.path.isfile(pentest_path):
                            return f"![{pentest_path}](file://{pentest_path})"
                   
                    return alt_text
                elif url in pollenisator_files:
                    pollenisator_base_dir = os.path.normpath(os.path.join(getMainDir(), "files", "pollenisator", "file", "unassigned"))
                    pollenisator_path = os.path.normpath(os.path.join(pollenisator_base_dir, os.path.basename(url)))
                    if pollenisator_path.startswith(pollenisator_base_dir):
                        if os.path.isfile(pollenisator_path):
                            return f"![{pollenisator_path}](file://{pollenisator_path})"
                    return alt_text
                else:
                    return match.group(0)
            obj = re.sub(pattern, repl, obj)
        return obj

    _recursive_process(context, 0)

