# dojo/tools/rapid7/parser.py
import logging
import re
from defusedxml import ElementTree
from dojo.models import Endpoint, Finding

logger = logging.getLogger(__name__)


class Rapid7Parser:
    """Parser for Rapid7 XML reports."""

    def get_fields(self) -> list[str]:
        """Return the list of fields used in the Rapid7 Parser."""
        return [
            "title", "url", "severity", "description", "mitigation",
            "false_p", "duplicate", "out_of_scope", "dynamic_finding",
            "impact", "unique_id_from_tool", "vuln_id_from_tool", "cve", "cwe"
        ]

    def get_dedupe_fields(self) -> list[str]:
        """Return the list of dedupe fields used in the Rapid7 Parser."""
        return ["title", "cve", "description"]

    def get_scan_types(self):
        return ["Rapid7 Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Rapid7 Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Rapid7 XML report format."

    def get_findings(self, xml_output, test):
        try:
            tree = ElementTree.parse(xml_output, ElementTree.XMLParser())
            return self.get_items(tree, test)
        except Exception as e:
            logger.error(f"Error parsing Rapid7 XML file: {e}")
            return []

    def get_items(self, tree, test):
        items = {}
        root = tree.getroot()
        
        # Handle different root element names
        if root.tag not in ["xml", "report", "vulnerabilities"]:
            logger.error("Invalid Rapid7 XML format")
            return []
        
        for vuln_node in tree.findall(".//vulnerability") + tree.findall(".//Vulnerability"):
            try:
                item = self.get_item(vuln_node, test)
                if item:
                    dupe_key = item.unique_id_from_tool or item.title
                    if dupe_key in items:
                        items[dupe_key].unsaved_endpoints.extend(item.unsaved_endpoints)
                        items[dupe_key].description += f"\n\n{item.description}"
                    else:
                        items[dupe_key] = item
            except Exception as e:
                logger.error(f"Error processing vulnerability node: {e}")
                continue
        
        return list(items.values())

    def get_item(self, vuln_node, test):
        """Extract finding information from a vulnerability node."""
        try:
            # Extract basic information
            title = self._get_text(vuln_node, "title") or self._get_text(vuln_node, "name") or "Unknown Vulnerability"
            severity = self._convert_severity(self._get_text(vuln_node, "severity") or self._get_text(vuln_node, "risk"))
            description = self._get_text(vuln_node, "description") or ""
            solution = self._get_text(vuln_node, "solution") or self._get_text(vuln_node, "remediation") or ""
            
            # Extract CVE and CWE
            cve = self._extract_cve(vuln_node)
            cwe = self._extract_cwe(vuln_node)
            
            # Extract host information
            host = self._get_text(vuln_node, "host") or self._get_text(vuln_node, "ip") or ""
            port = self._get_text(vuln_node, "port") or ""
            protocol = self._get_text(vuln_node, "protocol") or ""
            
            # Build description
            full_description = ""
            if host:
                full_description += f"Host: {host}\n"
            if port and protocol:
                full_description += f"Port: {port}/{protocol}\n"
            full_description += f"\n{description}\n"
            
            # Create endpoint
            endpoint = Endpoint(host=host) if host else None
            if endpoint and port and protocol:
                endpoint.port = int(port)
                endpoint.protocol = protocol
            
            # Create finding
            finding = Finding(
                title=title,
                test=test,
                severity=severity,
                description=full_description,
                mitigation=solution,
                false_p=False,
                duplicate=False,
                out_of_scope=False,
                dynamic_finding=True,
                unique_id_from_tool=self._get_text(vuln_node, "id") or title,
                vuln_id_from_tool=self._get_text(vuln_node, "id") or title,
                cve=cve if cve else None,
                cwe=cwe if cwe else None
            )
            
            # Add endpoint if available
            if endpoint:
                finding.unsaved_endpoints = [endpoint]
            
            return finding
            
        except Exception as e:
            logger.error(f"Error creating finding: {e}")
            return None

    def _get_text(self, node, tag, default=None):
        """Safe text extraction from XML node."""
        element = node.find(tag)
        return element.text if element is not None and element.text else default

    def _convert_severity(self, severity_str):
        """Convert Rapid7 severity to DefectDojo severity."""
        if not severity_str:
            return "Info"
            
        severity_str = severity_str.lower()
        if "critical" in severity_str or "5" in severity_str:
            return "Critical"
        elif "high" in severity_str or "4" in severity_str:
            return "High"
        elif "medium" in severity_str or "3" in severity_str:
            return "Medium"
        elif "low" in severity_str or "2" in severity_str:
            return "Low"
        else:
            return "Info"

    def _extract_cve(self, vuln_node):
        """Extract CVE from Rapid7 vulnerability node."""
        cve_ref = self._get_text(vuln_node, "cve") or self._get_text(vuln_node, "cve_id") or ""
        if cve_ref:
            # Extract CVE number from string
            match = re.search(r'CVE-(\d{4}-\d{4,})', cve_ref)
            if match:
                return match.group(0)
        return None

    def _extract_cwe(self, vuln_node):
        """Extract CWE from Rapid7 vulnerability node."""
        cwe_ref = self._get_text(vuln_node, "cwe") or self._get_text(vuln_node, "cwe_id") or ""
        if cwe_ref:
            # Extract CWE number from string
            match = re.search(r'CWE-(\d+)', cwe_ref)
            if match:
                return int(match.group(1))
        return None