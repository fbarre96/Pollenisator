"""
HTML report generation module for Pollenisator
Provides HTML templating functionality using Jinja2
"""
from typing import Any, Dict, Tuple, Union
from pollenisator.core.components.logger_config import logger
import os
import jinja2
import base64
import re
import markdown
from pollenisator.core.components.utils import getMainDir
from pollenisator.server.modules.filemanager.filemanager import listFiles

translation: Dict[str, str] = {}


def b64encode(string):
    """
    Base64 encode a string for embedding in HTML
    
    Args:
        string: The string to encode
        
    Returns:
        str: Base64 encoded string
    """
    return base64.b64encode(string.encode()).decode()


def translate(w):
    """
    Translate a word or list of words using the global translation dictionary
    
    Args:
        w: Word or list of words to translate
        
    Returns:
        Translated word(s)
    """
    if isinstance(w, list):
        trads = []
        for x in w:
            trads.append(translation.get(x, x))
        return trads
    return translation.get(w, w)


def getInitials(words):
    """
    Get initials from words or comma-separated list of words
    
    Args:
        words: String or list of words
        
    Returns:
        str: Comma-separated initials
    """
    initials = []
    if isinstance(words, str):
        words = words.split(",")
    for word in words:
        try:
            word_str = "".join([x[0] for x in word.split(" ")])  # Active Directory -> AD
        except:
            word_str = ""
        initials.append(word_str)
    return ", ".join(initials)


def regex_findall(string, pattern):
    """
    Find all regex matches in a string
    
    Args:
        string: Input string
        pattern: Regex pattern
        
    Returns:
        list: List of matches
    """
    return re.findall(pattern, string)


def debug(string):
    """
    Debug filter for templates - logs the value and returns it
    
    Args:
        string: Value to debug
        
    Returns:
        The original value
    """
    logger.debug("DEBUG FILTER: %s", str(string))
    return string


def markdown_to_html(text):
    """
    Convert markdown text to HTML
    
    Args:
        text: Markdown text to convert
        
    Returns:
        str: HTML converted text
    """
    if not isinstance(text, str):
        return text
    
    md = markdown.Markdown(extensions=['extra', 'codehilite', 'tables'])
    
    html = md.convert(text)
    if html.startswith("<p>") and html.endswith("</p>"):
        return html[3:-4]
    return html



def setup_context_images(context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Setup the context for the HTML report by processing images/proofs.
    Convert file paths to data URLs for inline embedding in HTML.
    
    Args:
        context (Dict[str, Any]): The context for the report, including defects and their proofs.
        
    Returns:
        Dict[str, Any]: The updated context with base64 encoded images
    """
    context["proof_by_names"] = {}
    
    for defect in context["defects"]:
        proofs = defect.get("proofs", [])
        proofs_by_name = {}
        
        # Build a lookup dictionary of proof files by name
        for proof in proofs:
            proofs_by_name[os.path.basename(proof)] = proof
        
        # Process description paragraphs for inline image references
        for i, para in enumerate(defect.get("description_paragraphs", [])):
            re_matches = re.finditer(r"!\[(.*)\]\(.*\)", para.strip())
            for re_match in re_matches:
                image_name = re_match.group(1).strip()
                if image_name in proofs_by_name:
                    proof_path = proofs_by_name[image_name]
                    if os.path.isfile(proof_path):
                        try:
                            # Read image file and convert to base64 data URL
                            with open(proof_path, 'rb') as img_file:
                                img_data = img_file.read()
                                img_extension = os.path.splitext(proof_path)[1].lower()
                                mime_type = {
                                    '.png': 'image/png',
                                    '.jpg': 'image/jpeg', 
                                    '.jpeg': 'image/jpeg',
                                    '.gif': 'image/gif',
                                    '.bmp': 'image/bmp',
                                    '.svg': 'image/svg+xml'
                                }.get(img_extension, 'image/png')
                                
                                img_b64 = base64.b64encode(img_data).decode()
                                data_url = f"data:{mime_type};base64,{img_b64}"
                                
                                # Replace markdown image syntax with HTML img tag
                                defect["description_paragraphs"][i] = para.replace(
                                    re_match.group(0), 
                                    f'<img src="{data_url}" alt="{image_name}" style="max-width: 100%; height: auto;">'
                                )
                                
                                context["proof_by_names"][os.path.basename(proof_path)] = data_url
                                
                        except Exception as e:
                            logger.warning(f"Failed to process image {proof_path}: {e}")
                            # Keep original markdown syntax if processing fails
                    else:
                        raise ValueError(f"Proof file not found: {image_name} for defect {defect.get('title', '')}")
        
        # Process instance proofs
        for instance in defect.get("instances", []):
            processed_proofs = []
            for proof in instance.get("proofs", []):
                if os.path.isfile(proof):
                    try:
                        with open(proof, 'rb') as img_file:
                            img_data = img_file.read()
                            img_extension = os.path.splitext(proof)[1].lower()
                            mime_type = {
                                '.png': 'image/png',
                                '.jpg': 'image/jpeg',
                                '.jpeg': 'image/jpeg', 
                                '.gif': 'image/gif',
                                '.bmp': 'image/bmp',
                                '.svg': 'image/svg+xml'
                            }.get(img_extension, 'image/png')
                            
                            img_b64 = base64.b64encode(img_data).decode()
                            data_url = f"data:{mime_type};base64,{img_b64}"
                            processed_proofs.append(data_url)
                    except Exception as e:
                        logger.warning(f"Failed to process instance proof {proof}: {e}")
                        processed_proofs.append(proof)  # Keep original path if processing fails
                else:
                    processed_proofs.append(proof)
            instance["proofs"] = processed_proofs
    
    return context


def recursiveEdits(obj, pentest_name):
    """
    Recursively edit object to replace file references with proper paths and convert markdown to HTML
    
    Args:
        obj: Object to process
        pentest_name: Name of the pentest for file path resolution
    """
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key in ["file", "files"] and isinstance(value, str):
                obj[key] = os.path.join(getMainDir(), "files", pentest_name, value)
            if isinstance(value, str):
                # Convert markdown to html for text content
                obj[key] = markdown_to_html(value)
            elif isinstance(value, (dict, list)):
                recursiveEdits(value, pentest_name)
    elif isinstance(obj, list):
        for item in obj:
            recursiveEdits(item, pentest_name)
def createReport(context: Dict[str, Any], template: str, out_name: str, **kwargs: Any) -> Union[Tuple[bool, str], Tuple[bool, str]]:
    """
    Create an HTML report based on a Jinja2 template and context.
    
    Args:
        context (Dict[str, Any]): The context for the report, including defects and their proofs.
        template (str): The path to the HTML template file.
        out_name (str): The name of the output file.
        **kwargs (Any): Additional parameters, including the translation.
        
    Returns:
        Union[Tuple[bool, str], Tuple[bool, str]]: A tuple containing a boolean indicating whether 
        the operation was successful, and a string containing the path to the generated report 
        or an error message.
    """
    global translation
    translation = kwargs.get("translation", {})
    
    try:
        # Setup Jinja2 environment with custom filters
        jinja_env = jinja2.Environment(
            autoescape=jinja2.select_autoescape(['html', 'xml']),
            loader=jinja2.FileSystemLoader(os.path.dirname(template))
        )
        
        # Add custom filters
        jinja_env.filters['translate'] = translate
        jinja_env.filters['b64encode'] = b64encode
        jinja_env.filters['getInitials'] = getInitials
        jinja_env.filters['regex_findall'] = regex_findall
        jinja_env.filters['debug'] = debug
        jinja_env.filters['markdown_to_html'] = markdown_to_html
        
        # Setup context with image processing
        try:
            context = setup_context_images(context)
        except ValueError as e:
            return False, str(e)  # Image file not found
        
        # Process file references recursively
        recursiveEdits(context, context["pentest"])
        
        # Render the template
        template_obj = jinja_env.get_template(os.path.basename(template))
        rendered_html = template_obj.render(context)
        
        # Determine output path
        dir_path = os.path.dirname(os.path.realpath(__file__))
        out_path = os.path.join(dir_path, "../../exports/", out_name + ".html")
        
        # Ensure exports directory exists
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        
        # Write the rendered HTML to file
        with open(out_path, 'w', encoding='utf-8') as output_file:
            output_file.write(rendered_html)
        
        # Also save a copy to /tmp for temporary access
        tmp_path = f"/tmp/{out_name}.html"
        with open(tmp_path, 'w', encoding='utf-8') as tmp_file:
            tmp_file.write(rendered_html)
            
        logger.info("Generated HTML report at %s", str(out_path))
        return True, out_path
        
    except jinja2.exceptions.TemplateSyntaxError as e:
        return False, f"Error in template syntax on line {e.lineno}: {str(e)}"
    except jinja2.exceptions.UndefinedError as e:
        return False, f"Undefined variable in template: {str(e)}"
    except FileNotFoundError:
        return False, f"Template file not found: {template}"
    except jinja2.exceptions.TemplateNotFound as e:
        return False, f"Template not found in environment: {str(e)}"
    except Exception as e:
        logger.error(f"Error generating HTML report: {e}")
        return False, f"Error generating HTML report: {str(e)}"
