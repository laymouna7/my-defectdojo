import logging
import re
from defusedxml import ElementTree
from dojo.models import Endpoint, Finding

logger = logging.getLogger(__name__)


class NessusParser:
    """Parser for Nessus XML reports."""

    def get_fields(self) -> list[str]:
        """Return the list of fields used in the Nessus Parser."""
        return [
            "title", "url", "severity", "description", "mitigation",
            "false_p", "duplicate", "out_of_scope", "dynamic_finding",
            "impact", "unique_id_from_tool", "vuln_id_from_tool", "cve", "cwe"
        ]

    def get_dedupe_fields(self) -> list[str]:
        """Return the list of dedupe fields used in the Nessus Parser."""
        return ["title", "cve", "description"]

    def get_scan_types(self):
        return ["Nessus Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Nessus Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Nessus XML report format."

    def get_findings(self, xml_output, test):
        try:
            tree = ElementTree.parse(xml_output, ElementTree.XMLParser())
            return self.get_items(tree, test)
        except Exception as e:
            logger.error(f"Error parsing Nessus XML file: {e}")
            return []

    def get_items(self, tree, test):
        items = {}
        root = tree.getroot()
        
        # Handle different root element names
        if root.tag not in ["NessusClientData_v2", "NessusClientData"]:
            logger.error("Invalid Nessus XML format")
            return []
        
        for report_host in tree.findall(".//ReportHost"):
            host_name = report_host.get("name", "")
            
            for report_item in report_host.findall("ReportItem"):
                try:
                    item = self.get_item(report_item, host_name, test)
                    if item:
                        dupe_key = item.unique_id_from_tool or item.title
                        if dupe_key in items:
                            items[dupe_key].unsaved_endpoints.extend(item.unsaved_endpoints)
                            items[dupe_key].description += f"\n\n{item.description}"
                        else:
                            items[dupe_key] = item
                except Exception as e:
                    logger.error(f"Error processing report item: {e}")
                    continue
        
        return list(items.values())

    def get_item(self, report_item, host_name, test):
        """Extract finding information from a ReportItem node."""
        try:
            # Extract basic information
            plugin_id = report_item.get("pluginID", "")
            plugin_name = report_item.get("pluginName", "Unknown Vulnerability")
            port = report_item.get("port", "")
            protocol = report_item.get("protocol", "")
            severity = self._convert_severity(report_item.get("severity", "0"))
            
            # Extract description and solution
            description = self._get_text(report_item, "description", "")
            synopsis = self._get_text(report_item, "synopsis", "")
            solution = self._get_text(report_item, "solution", "")
            plugin_output = self._get_text(report_item, "plugin_output", "")
            
            # Extract CVE and CWE
            cve = self._get_text(report_item, "cve", "")
            cwe = self._extract_cwe(report_item)
            
            # Build description
            full_description = f"Host: {host_name}\n"
            if port and protocol:
                full_description += f"Port: {port}/{protocol}\n"
            if synopsis:
                full_description += f"\nSynopsis:\n{synopsis}\n"
            if description:
                full_description += f"\nDescription:\n{description}\n"
            if plugin_output:
                full_description += f"\nPlugin Output:\n{plugin_output}\n"
            
            # Create endpoint
            endpoint = Endpoint(host=host_name)
            if port and protocol:
                endpoint.port = int(port)
                endpoint.protocol = protocol
            
            # Create finding
            finding = Finding(
                title=plugin_name,
                test=test,
                severity=severity,
                description=full_description,
                mitigation=solution,
                false_p=False,
                duplicate=False,
                out_of_scope=False,
                dynamic_finding=True,
                unique_id_from_tool=plugin_id,
                vuln_id_from_tool=plugin_id,
                cve=cve if cve else None,
                cwe=cwe if cwe else None
            )
            
            # Add endpoint
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
        """Convert Nessus severity to DefectDojo severity."""
        severity_map = {
            "0": "Info",
            "1": "Low",
            "2": "Medium",
            "3": "High",
            "4": "Critical"
        }
        return severity_map.get(severity_str, "Info")

    def _extract_cwe(self, report_item):
        """Extract CWE from Nessus report item."""
        # Check for CWE in plugin_name or description
        cwe_ref = self._get_text(report_item, "cwe", "")
        if cwe_ref:
            # Extract CWE number from string
            match = re.search(r'CWE-(\d+)', cwe_ref)
            if match:
                return int(match.group(1))
        
        # Additional CWE extraction logic can be added here
        return None