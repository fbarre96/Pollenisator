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

def setup_context_proofs(doc: DocxTemplate, context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Setup the context for the report by replacing proof file paths with InlineImage objects.
    Args:
        doc (DocxTemplate): The document template.
        context (Dict[str, Any]): The context for the report, including defects and their proofs.
    Raises:
        ValueError: If a proof file is not found.
    Returns:
        Dict[str, Any]: The updated context with InlineImage objects for proofs.
    """
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
                        raise ValueError(f"Proof file not found : {str(re_match.group(1).strip())} for defect {str(defect.get('title', ''))}")
                    defect["description_paragraphs"][i] = InlineImage(doc, proof, width=Cm(17))
                    context["proof_by_names"][os.path.basename(proof)] = defect["description_paragraphs"][i]
        for instance in defect.get("instances", []):
            for i,proof in enumerate(instance.get("proofs", [])):
                instance["proofs"][i] = InlineImage(doc, proof)
    return context

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
    try:
        context = setup_context_proofs(doc, context)
    except ValueError as e:
        return False, str(e) # Proof file not found
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
        "Table":"StyleTableau" },
        mermaid_cli=os.environ.get("MARKDOWN_MERMAID_CLI", None),
        mermaid_server_link=os.environ.get("MARKDOWN_MERMAID_SERVER", None),
    )
    if not result:
        return False, "Error in Markdown conversion : "+str(msg)
    logger.info("Generated report at %s", str(out_path))
    return True, out_path


regex_replace_lonely_lf = re.compile(r"(?<!\n)\n(?!\n)")
regex_replace_images = re.compile(r"(?<!\n\n)(!\[.*\]\((.*?)\))")
regex_replace_images_no_newline = re.compile(r"(!\[.*\]\((.*?)\))(?!\n\n)")

# Maximum recursion depth for context processing
MAX_RECURSION_DEPTH = 10

def _get_file_path_if_exists(url: str, file_list: list, base_path_parts: list) -> str:
    """
    Helper function to check if a URL exists in the file list and return the file path if it exists.
    
    Args:
        url (str): The URL to check
        file_list (list): List of files to check against
        base_path_parts (list): Parts of the base path to construct the full path
        
    Returns:
        str: The file path with file:// prefix if found and exists, empty string otherwise
    """
    if url not in file_list:
        return ""
        
    base_dir = os.path.normpath(os.path.join(getMainDir(), *base_path_parts))
    file_path = os.path.normpath(os.path.join(base_dir, os.path.basename(url)))
    
    if file_path.startswith(base_dir) and os.path.isfile(file_path):
        return f"![{file_path}](file://{file_path})"
    
    return ""

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
    
    def _create_replacement_function():
        """Create the replacement function for markdown images."""
        def repl(match):
            alt_text = match.group(1)
            url = match.group(2)
            
            # Try pentest files first
            file_path = _get_file_path_if_exists(url, files, ["files", pentest, "file", "unassigned"])
            if file_path:
                return file_path
            
            # Try pollenisator files
            file_path = _get_file_path_if_exists(url, pollenisator_files, ["files", "pollenisator", "file", "unassigned"])
            if file_path:
                return file_path
            
            # If neither found, return original alt text
            if url in files or url in pollenisator_files:
                return alt_text
            else:
                return match.group(0)
        return repl
    
    replacement_func = _create_replacement_function()
    
    def _recursive_process(obj, depth: int):
        if depth > MAX_RECURSION_DEPTH:
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
            obj = re.sub(pattern, replacement_func, obj)
        return obj

    _recursive_process(context, 0)

