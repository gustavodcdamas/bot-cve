from .base_collector import BaseCollector
from datetime import datetime, timedelta
import feedparser
import requests
import os

class OpenCVECollector(BaseCollector):
    def __init__(self):
        super().__init__("OpenCVE", rate_limit_delay=1.0)
        self.api_url = "https://www.opencve.io/api/cve"
        self.api_key = os.getenv('OPENCVE_API_KEY')
    
    def collect_cves(self):
        """Coleta CVEs do OpenCVE"""
        if not self.api_key:
            print(f"[{self.name}] API key não configurada, pulando...")
            return []
        
        try:
            params = {
                "limit": 20,
                "sort": "-created_at"
            }
            
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
            
            response = self.safe_request(self.api_url, params=params, headers=headers)
            if not response:
                return []
            
            data = response.json()
            cves = []
            
            for item in data.get("data", []):
                cve_data = {
                    "id": item.get("id", "OPENCVE-UNKNOWN"),
                    "title": item.get("summary", "")[:100] + "..." if len(item.get("summary", "")) > 100 else item.get("summary", ""),
                    "description": item.get("summary", ""),
                    "published": item.get("created_at", ""),
                    "cvss": item.get("cvss", {}).get("base_score"),
                    "severity": item.get("cvss", {}).get("base_severity", "UNKNOWN").upper(),
                    "references": [f"https://www.opencve.io/cve/{item.get('id', '')}"],
                    "source": self.name
                }
                cves.append(cve_data)
            
            return cves
        except Exception as e:
            print(f"[{self.name}] Erro: {e}")
            return []