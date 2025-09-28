from .base_collector import BaseCollector
from datetime import datetime, timedelta
import feedparser
import requests
import os

class GitHubAdvisoryCollector(BaseCollector):
    def __init__(self):
        super().__init__("GitHub", rate_limit_delay=1.0)
        self.api_url = "https://api.github.com/advisories"
        self.token = os.getenv('GITHUB_TOKEN')
    
    def collect_cves(self):
        """Coleta advisories do GitHub"""
        params = {
            "per_page": 20,
            "sort": "published",
            "direction": "desc"
        }
        
        # Adiciona headers com token se disponível
        headers = {}
        if self.token:
            headers['Authorization'] = f'token {self.token}'
            headers['Accept'] = 'application/vnd.github.v3+json'
        
        response = self.safe_request(self.api_url, params=params, headers=headers)
        if not response:
            return []
        
        try:
            advisories = response.json()
            cves = []
            
            for advisory in advisories:
                cve_data = {
                    "id": advisory.get("cve_id") or advisory.get("ghsa_id", "GITHUB-UNKNOWN"),
                    "title": advisory.get("summary", ""),
                    "description": advisory.get("description", ""),
                    "published": advisory.get("published_at", ""),
                    "cvss": advisory.get("cvss", {}).get("score") if advisory.get("cvss") else None,
                    "severity": advisory.get("severity", "UNKNOWN").upper(),
                    "references": [advisory.get("html_url", "")],
                    "source": self.name
                }
                cves.append(cve_data)
            
            return cves
        except Exception as e:
            print(f"[{self.name}] Erro: {e}")
            return []