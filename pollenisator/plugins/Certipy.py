"""A plugin to parse Certipy JSON output"""

from typing import IO, Any, Dict, List, Optional, Tuple
from pollenisator.core.components.tag import Tag
from pollenisator.plugins.plugin import Plugin
from pollenisator.core.models.ip import Ip
from pollenisator.server.modules.activedirectory.users import User
from pollenisator.server.modules.activedirectory.computers import Computer
from pollenisator.core.models.port import Port
import json


def parse_certipy_output(file_opened):
    """
    Parse Certipy JSON output file
    
    Args:
        file_opened: opened Certipy JSON file
    
    Returns:
        Dictionary with parsed data or None if parsing fails
        
    Example Certipy output structure:
    {
        "Certificate Authorities": {
            "0": {
                "CA Name": "CA-NAME",
                "DNS Name": "dc.domain.local",
                "Certificate Subject": "CN=CA-NAME, DC=domain, DC=local",
                "Certificate Serial Number": "...",
                "Certificate Validity Start": "...",
                "Certificate Validity End": "...",
                "Web Enrollment": "Disabled",
                "User Specified SAN": "Disabled",
                "Request Disposition": "Issue",
                "Enforce Encryption for Requests": "Enabled"
            }
        },
        "Certificate Templates": {
            "0": {
                "Template Name": "TemplateName",
                "Display Name": "Template Display Name",
                "Certificate Authorities": ["CA-NAME"],
                "Enabled": true,
                "Client Authentication": true,
                "Enrollment Agent": false,
                "Any Purpose": false,
                "Enrollee Supplies Subject": false,
                "Certificate Name Flag": ["EnrolleeSuppliesSubject"],
                "Enrollment Flag": ["IncludeSymmetricAlgorithms", "PublishToDs"],
                "Private Key Flag": ["ExportableKey"],
                "Extended Key Usage": ["Client Authentication"],
                "Requires Manager Approval": false,
                "Requires Key Archival": false,
                "Authorized Signatures Required": 0,
                "Validity Period": "1 year",
                "Renewal Period": "6 weeks",
                "Minimum RSA Key Length": 2048,
                "Permissions": {
                    "Enrollment Permissions": {
                        "Enrollment Rights": ["Domain Admins", "Enterprise Admins"],
                        "All Extended Rights": []
                    },
                    "Write Permissions": {
                        "Owner": "Administrator",
                        "Full Control": [],
                        "Write DACL": [],
                        "Write Owner": []
                    }
                },
                "[!] Vulnerabilities": {
                    "ESC1": "...",
                    "ESC2": "...",
                    "ESC3": "..."
                }
            }
        }
    }
    """
    try:
        data = json.load(file_opened)
    except (json.JSONDecodeError, Exception):
        return None
    
    # Validate that this is a Certipy output
    if not isinstance(data, dict):
        return None
    
    # Check for typical Certipy keys
    has_certipy_keys = any(key in data for key in ["Certificate Authorities", "Certificate Templates"])
    if not has_certipy_keys:
        return None
    
    return data


def process_certificate_authorities(pentest, cas_data):
    """
    Process Certificate Authorities data
    
    Args:
        pentest: pentest name
        cas_data: Certificate Authorities data from Certipy
        
    Returns:
        Tuple of (notes, tags, inserted_count)
    """
    notes = ""
    tags = []
    inserted = 0
    ip_o = None
    if not cas_data:
        return notes, tags, inserted
    
    notes += "=== Certificate Authorities ===\n"
    
    for ca_id, ca_info in cas_data.items():
        ca_name = ca_info.get("CA Name", "Unknown")
        dns_name = ca_info.get("DNS Name", "")
        web_enrollment = ca_info.get("Web Enrollment", "Unknown")
        
        notes += f"\nCA: {ca_name}\n"
        notes += f"  DNS: {dns_name}\n"
        notes += f"  Web Enrollment: {web_enrollment}\n"
        
        # Extract IP or hostname from DNS name
        if dns_name:
            # Remove port if present
            host = dns_name.split(":")[0]
            
            # Create or update IP entry
            ip_o = Ip(pentest).initialize(
                host,
                infos={
                    "plugin": Certipy.get_name(),
                    "ca_name": ca_name,
                    "web_enrollment": web_enrollment
                }
            )
            result = ip_o.addInDb()
            if result["res"]:
                inserted += 1
            # If web enrollment is enabled, note the HTTP/HTTPS service
            if web_enrollment.lower() == "enabled":
                ip_o.addTag(Tag("certipy-web-enrollment", "blue", level="info"))

    
    return notes, tags, inserted, ip_o


def process_certificate_templates(pentest, templates_data, ip_o):
    """
    Process Certificate Templates data
    
    Args:
        pentest: pentest name
        templates_data: Certificate Templates data from Certipy
        
    Returns:
        Tuple of (notes, tags, vulnerable_templates)
    """
    notes = ""
    tags = []
    vulnerable_templates = []
    
    if not templates_data:
        return notes, tags, vulnerable_templates
    
    notes += "\n=== Certificate Templates ===\n"
    
    for template_id, template_info in templates_data.items():
        template_name = template_info.get("Template Name", "Unknown")
        enabled = template_info.get("Enabled", False)
        vulnerabilities = template_info.get("[!] Vulnerabilities", {})
        
        notes += f"\nTemplate: {template_name}\n"
        notes += f"  Enabled: {enabled}\n"
        
        # Check for vulnerabilities
        if vulnerabilities:
            notes += "  [!] VULNERABILITIES FOUND:\n"
            for vuln_type, vuln_desc in vulnerabilities.items():
                notes += f"    - {vuln_type}: {vuln_desc}\n"
                vulnerable_templates.append({
                    "template": template_name,
                    "vulnerability": vuln_type,
                    "description": vuln_desc
                })
            
            # Add high priority tag if vulnerabilities exist
            if enabled:
                if ip_o is not None:
                    ip_o.addTag(Tag("certipy-vulnerable-template", "red", level="critical"))
                else:
                    tags.append(Tag("certipy-vulnerable-template", "red", level="critical"))
            else:
                if ip_o is not None:
                    ip_o.addTag(Tag("certipy-vulnerable-template-disabled", "orange", level="high"))
                else:
                    tags.append(Tag("certipy-vulnerable-template-disabled", "orange", level="high"))
        
        # List key properties
        client_auth = template_info.get("Client Authentication", False)
        enrollee_supplies_subject = template_info.get("Enrollee Supplies Subject", False)
        requires_manager_approval = template_info.get("Requires Manager Approval", False)
        
        notes += f"  Client Authentication: {client_auth}\n"
        notes += f"  Enrollee Supplies Subject: {enrollee_supplies_subject}\n"
        notes += f"  Requires Manager Approval: {requires_manager_approval}\n"
        
        # Check for potentially interesting configurations
        if enrollee_supplies_subject and not requires_manager_approval:
            notes += "  [!] Potentially exploitable: Enrollee supplies subject without approval\n"
    
    return notes, tags, vulnerable_templates


class Certipy(Plugin):
    """
    Certipy plugin for parsing Certipy JSON output
    Certipy is a tool for Active Directory Certificate Services enumeration and abuse
    """
    
    default_bin_names = ["certipy", "certipy-ad"]
    
    def getFileOutputArg(self):
        """
        Returns the command line parameter giving the output file
        
        Returns:
            string
        """
        return " -json -output "
    
    def getFileOutputExt(self):
        """
        Returns the expected file extension for this command result file
        
        Returns:
            string
        """
        return ".json"
    
    def getFileOutputPath(self, commandExecuted):
        """
        Returns the output file path given in the executed command using getFileOutputArg
        
        Args:
            commandExecuted: the command that was executed with an output file inside.
            
        Returns:
            string: the path to file created
        """
        return commandExecuted.split(self.getFileOutputArg())[-1].strip().split(" ")[0]
    
    def getTags(self):
        """
        Returns a list of tags that can be added by this plugin
        
        Returns:
            dict of tags
        """
        return {
            "certipy-info": Tag("certipy-info", level="info"),
            "certipy-web-enrollment": Tag("certipy-web-enrollment", "blue", level="info"),
            "certipy-vulnerable-template": Tag("certipy-vulnerable-template", "red", level="critical"),
            "certipy-vulnerable-template-disabled": Tag("certipy-vulnerable-template-disabled", "orange", level="high")
        }
    
    def Parse(self, pentest: str, file_opened: IO[bytes], **kwargs: Dict[str, Any]) -> Tuple[Optional[str], Optional[List[Tag]], Optional[str], Optional[Dict[str, Optional[Dict[str, Optional[str]]]]]]:
        """
        Parse an opened Certipy JSON file to extract certificate information
        
        Args:
            pentest (str): The name of the pentest
            file_opened (IO[bytes]): The opened file
            **kwargs: Additional parameters
            
        Returns:
            Tuple with 4 values (All set to None if parsing wrong file):
                0. notes (str): Notes to be inserted in tool
                1. tags (List[Tag]): A list of tags to be added to tool
                2. lvl (str): The level of the command executed
                3. targets (Dict): Dictionary of targeted objects
        """
        # Check file extension
        if kwargs.get("ext", "").lower() != self.getFileOutputExt():
            return None, None, None, None
        
        # Parse the file
        parsed_data = parse_certipy_output(file_opened)
        if parsed_data is None:
            return None, None, None, None
        
        # Initialize return values
        all_notes = "Certipy Results\n" + "="*50 + "\n\n"
        all_tags = [self.getTags()["certipy-info"]]
        targets = {}
        
        # Process Certificate Authorities
        cas_data = parsed_data.get("Certificate Authorities", {})
        ca_notes, ca_tags, ca_inserted, ip_o = process_certificate_authorities(pentest, cas_data)
        all_notes += ca_notes
        all_tags.extend(ca_tags)
        
        # Process Certificate Templates
        templates_data = parsed_data.get("Certificate Templates", {})
        template_notes, template_tags, vulnerable_templates = process_certificate_templates(
            pentest, templates_data, ip_o
        )
        all_notes += template_notes
        all_tags.extend(template_tags)
        
        # Add summary
        summary = f"\n\n=== Summary ===\n"
        summary += f"Certificate Authorities found: {len(cas_data)}\n"
        summary += f"Certificate Templates found: {len(templates_data)}\n"
        summary += f"Vulnerable templates: {len(vulnerable_templates)}\n"
        
        if vulnerable_templates:
            summary += "\n[!] VULNERABLE TEMPLATES:\n"
            for vuln in vulnerable_templates:
                summary += f"  - {vuln['template']}: {vuln['vulnerability']}\n"
        
        all_notes += summary
        
        # Return at wave level since this is domain-wide information
        return all_notes, all_tags, "wave", {"wave": None}
