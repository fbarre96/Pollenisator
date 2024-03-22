from typing import Any, Dict, Tuple, Union
from pollenisator.core.components.logger_config import logger
import os
from docxtpl import DocxTemplate
from docxtpl import InlineImage
import jinja2
from markdowntodocx.markdownconverter import convertMarkdownInFile
import re
from docx.shared import Cm

translation: Dict[str, str] = {}

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
    jinja_env.filters['getInitials'] = getInitials
    for defect in context["defects"]:
        proofs =  defect.get("proofs", [])
        proofs_by_name = {}
        for proof in proofs:
            proofs_by_name[os.path.basename(proof)] = proof
        if proofs:
            for i, para in enumerate(defect.get("description_paragraphs", [])):
                re_matches = re.finditer(r"!\[(.*)\]\(.*\)", para.strip())
                for re_match in re_matches:
                    if re_match.group(1).strip() in proofs_by_name:
                        proof = proofs_by_name[re_match.group(1).strip()]
                        if not os.path.isfile(proof):
                            return False, f"Proof file not found : {str(re_match.group(1).strip())} for defect {str(defect.get('title', ''))}"
                        defect["description_paragraphs"][i] = InlineImage(doc, proof, width=Cm(17))
        for instance in defect.get("instances", []):
            for i,proof in enumerate(instance.get("proofs", [])):
                instance["proofs"][i] = InlineImage(doc, proof)
    try:
        doc.render(context, jinja_env)
    except jinja2.exceptions.TemplateSyntaxError as e:
        return False, "Error in template syntax : "+str(e)
    dir_path = os.path.dirname(os.path.realpath(__file__))
    out_path = os.path.join(dir_path, "../../exports/", out_name+".docx")
    doc.save(out_path)
    logger.info("Converting Markdown of %s", str(out_path))
    result, msg = convertMarkdownInFile(out_path, out_path, {"Header":"Sous-défaut"})
    if not result:
        return False, "Error in Markdown conversion : "+str(msg)
    logger.info("Generated report at %s", str(out_path))
    return True, out_path
