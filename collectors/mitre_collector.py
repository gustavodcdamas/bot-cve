from .base_collector import BaseCollector
from datetime import datetime, timedelta
import feedparser
import requests
import os

class MITRECollector(BaseCollector):
    def __init__(self):
        super().__init__("MITRE", rate_limit_delay=1.0)
        self.api_url = "https://cveawg.mitre.org/api/cve"
    
    def collect_cves(self):
        """Coleta CVEs do MITRE"""
        try:
            # MITRE CVE API é mais complexa, implementação básica
            params = {
                "limit": 20,
                "sort": "datePublished",
                "order": "desc"
            }
            
            response = self.safe_request(self.api_url, params=params)
            if not response:
                return []
            
            data = response.json()
            cves = []
            
            for item in data.get("cveRecords", []):
                cve_data = {
                    "id": item.get("cveMetadata", {}).get("cveId", "MITRE-UNKNOWN"),
                    "title": item.get("containers", {}).get("cna", {}).get("title", ""),
                    "description": self._extract_description(item),
                    "published": item.get("cveMetadata", {}).get("datePublished", ""),
                    "cvss": None,
                    "severity": "UNKNOWN",
                    "references": self._extract_references(item),
                    "source": self.name
                }
                cves.append(cve_data)
            
            return cves
        except Exception as e:
            print(f"[{self.name}] Erro: {e}")
            return []
    
    def _extract_description(self, item):
        """Extrai descrição do formato MITRE"""
        try:
            descriptions = item.get("containers", {}).get("cna", {}).get("descriptions", [])
            for desc in descriptions:
                if desc.get("lang") == "en":
                    return desc.get("value", "")
            return "N/A"
        except:
            return "N/A"
    
    def _extract_references(self, item):
        """Extrai referências do formato MITRE"""
        try:
            references = item.get("containers", {}).get("cna", {}).get("references", [])
            return [ref.get("url", "") for ref in references if ref.get("url")]
        except:
            return []