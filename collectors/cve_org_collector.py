from .base_collector import BaseCollector
from datetime import datetime, timedelta
import feedparser
import requests
import os

class CVEOrgCollector(BaseCollector):
    def __init__(self):
        super().__init__("CVE.org", rate_limit_delay=1.0)
        self.api_url = "https://cveawg.mitre.org/api/cve"
    
    def collect_cves(self):
        """Coleta CVEs do CVE.org (MITRE)"""
        try:
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
                    "id": item.get("cveMetadata", {}).get("cveId", "CVE-ORG-UNKNOWN"),
                    "title": self._extract_title(item),
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
    
    def _extract_title(self, item):
        """Extrai título do formato CVE.org"""
        try:
            title = item.get("containers", {}).get("cna", {}).get("title", "")
            if not title:
                # Fallback para primeira linha da descrição
                desc = self._extract_description(item)
                title = desc.split('.')[0] if desc else "CVE.org Security Advisory"
            return title[:100] + "..." if len(title) > 100 else title
        except:
            return "CVE.org Security Advisory"
    
    def _extract_description(self, item):
        """Extrai descrição do formato CVE.org"""
        try:
            descriptions = item.get("containers", {}).get("cna", {}).get("descriptions", [])
            for desc in descriptions:
                if desc.get("lang") == "en":
                    return desc.get("value", "")
            return "N/A"
        except:
            return "N/A"
    
    def _extract_references(self, item):
        """Extrai referências do formato CVE.org"""
        try:
            references = item.get("containers", {}).get("cna", {}).get("references", [])
            urls = [ref.get("url", "") for ref in references if ref.get("url")]
            if not urls:
                cve_id = item.get("cveMetadata", {}).get("cveId", "")
                urls = [f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"]
            return urls
        except:
            return []