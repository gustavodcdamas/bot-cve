from .base_collector import BaseCollector
from datetime import datetime, timedelta
import feedparser
import requests
import os

class NPMSecurityCollector(BaseCollector):
    def __init__(self):
        super().__init__("NPM Security", rate_limit_delay=1.0)
        self.api_url = "https://registry.npmjs.org/-/npm/v1/security/advisories"
    
    def collect_cves(self):
        """Coleta advisories de segurança do NPM"""
        try:
            response = self.safe_request(self.api_url)
            if not response:
                return []
            
            data = response.json()
            cves = []
            
            # NPM retorna advisories
            for advisory_id, advisory in list(data.get("advisories", {}).items())[:10]:
                cve_data = {
                    "id": advisory.get("cves", [advisory_id])[0] if advisory.get("cves") else f"NPM-{advisory_id}",
                    "title": advisory.get("title", ""),
                    "description": advisory.get("overview", ""),
                    "published": advisory.get("created", ""),
                    "cvss": advisory.get("cvss_score"),
                    "severity": advisory.get("severity", "UNKNOWN").upper(),
                    "references": [advisory.get("url", "")],
                    "source": self.name
                }
                cves.append(cve_data)
            
            return cves
        except Exception as e:
            print(f"[{self.name}] Erro: {e}")
            return []