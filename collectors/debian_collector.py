from .base_collector import BaseCollector
from datetime import datetime, timedelta
import feedparser
import requests
import os

class DebianCollector(BaseCollector):
    def __init__(self):
        super().__init__("Debian Security", rate_limit_delay=1.0)
        self.rss_url = "https://www.debian.org/security/dsa.en.rdf"
        self.fallback_url = "https://security-tracker.debian.org/tracker/data/json"
    
    def collect_cves(self):
        """Coleta alertas de segurança do Debian"""
        try:
            # Tenta primeiro o RSS
            feed = feedparser.parse(self.rss_url)
            cves = []
            
            if feed.entries:
                for entry in feed.entries[:10]:
                    title = entry.get("title", "")
                    description = entry.get("summary", "")
                    
                    cve_data = {
                        "id": f"DSA-{entry.get('id', 'UNKNOWN')}",
                        "title": title,
                        "description": description,
                        "published": entry.get("published", ""),
                        "cvss": None,
                        "severity": "MEDIUM",
                        "references": [entry.get("link", "")],
                        "source": self.name
                    }
                    cves.append(cve_data)
            else:
                # Fallback: tenta API do security tracker
                cves = self._collect_from_security_tracker()
            
            return cves
        except Exception as e:
            print(f"[{self.name}] Erro: {e}")
            return []
    
    def _collect_from_security_tracker(self):
        """Coleta do Debian Security Tracker como fallback"""
        try:
            response = self.safe_request(self.fallback_url)
            if not response:
                return []
            
            data = response.json()
            cves = []
            
            # Pega as primeiras 10 CVEs
            for cve_id, cve_info in list(data.items())[:10]:
                if cve_id.startswith('CVE-'):
                    description = cve_info.get('description', 'Debian security update')
                    
                    cve_data = {
                        "id": cve_id,
                        "title": f"Debian Security Update - {cve_id}",
                        "description": description,
                        "published": "",
                        "cvss": None,
                        "severity": "MEDIUM",
                        "references": [f"https://security-tracker.debian.org/tracker/{cve_id}"],
                        "source": self.name
                    }
                    cves.append(cve_data)
            
            return cves
        except Exception as e:
            print(f"[{self.name}] Erro no fallback: {e}")
            return []