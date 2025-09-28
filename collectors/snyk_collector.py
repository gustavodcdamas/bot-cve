from .base_collector import BaseCollector
from datetime import datetime, timedelta
import feedparser
import requests
import os

class SnykCollector(BaseCollector):
    def __init__(self):
        super().__init__("Snyk", rate_limit_delay=1.0)
        self.rss_url = "https://security.snyk.io/rss/vulnerabilities.xml"
    
    def collect_cves(self):
        """Coleta vulnerabilidades do Snyk"""
        try:
            feed = feedparser.parse(self.rss_url)
            cves = []
            
            for entry in feed.entries[:15]:
                title = entry.get("title", "")
                description = entry.get("summary", "")
                
                # Extrai CVE ID se presente
                import re
                cve_match = re.search(r'CVE-\d{4}-\d{4,7}', title + " " + description)
                cve_id = cve_match.group(0) if cve_match else f"SNYK-{entry.get('id', 'UNKNOWN')}"
                
                cve_data = {
                    "id": cve_id,
                    "title": title,
                    "description": description,
                    "published": entry.get("published", ""),
                    "cvss": None,
                    "severity": self._extract_severity(title, description),
                    "references": [entry.get("link", "")],
                    "source": self.name
                }
                cves.append(cve_data)
            
            return cves
        except Exception as e:
            print(f"[{self.name}] Erro: {e}")
            return []
    
    def _extract_severity(self, title, description):
        """Extrai severidade do título/descrição"""
        text = (title + " " + description).lower()
        if any(word in text for word in ["critical", "severe"]):
            return "CRITICAL"
        elif any(word in text for word in ["high", "important"]):
            return "HIGH"
        elif any(word in text for word in ["medium", "moderate"]):
            return "MEDIUM"
        elif any(word in text for word in ["low", "minor"]):
            return "LOW"
        else:
            return "MEDIUM"  # Default