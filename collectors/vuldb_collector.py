from .base_collector import BaseCollector
from datetime import datetime, timedelta
import feedparser
import requests
import os

class VulDBCollector(BaseCollector):
    def __init__(self):
        super().__init__("VulDB", rate_limit_delay=2.0)
        self.api_key = os.getenv('VULDB_API_KEY')
        self.api_url = "https://vuldb.com/api/v1/recent"
        self.rss_url = "https://vuldb.com/?rss.recent"
    
    def collect_cves(self):
        """Coleta CVEs do VulDB"""
        if self.api_key:
            return self._collect_from_api()
        else:
            return self._collect_from_rss()
    
    def _collect_from_api(self):
        """Coleta usando API key"""
        try:
            headers = {
                'X-VulDB-ApiKey': self.api_key,
                'User-Agent': 'CVE-Bot/1.0'
            }
            
            response = self.safe_request(self.api_url, headers=headers)
            if not response:
                return []
            
            data = response.json()
            cves = []
            
            for item in data.get('result', [])[:10]:
                entry = item.get('entry', {})
                cve_data = {
                    "id": entry.get('cve', {}).get('id', f"VULDB-{entry.get('id', 'UNKNOWN')}"),
                    "title": entry.get('title', ''),
                    "description": entry.get('summary', ''),
                    "published": entry.get('timestamp', {}).get('create', ''),
                    "cvss": entry.get('cvss', {}).get('score'),
                    "severity": self._cvss_to_severity(entry.get('cvss', {}).get('score')),
                    "references": [f"https://vuldb.com/?id.{entry.get('id', '')}"],
                    "source": self.name
                }
                cves.append(cve_data)
            
            return cves
        except Exception as e:
            print(f"[{self.name}] Erro na API: {e}")
            return self._collect_from_rss()  # Fallback para RSS
    
    def _collect_from_rss(self):
        """Coleta usando RSS como fallback"""
        try:
            feed = feedparser.parse(self.rss_url)
            cves = []
            
            for entry in feed.entries[:10]:
                title = entry.get("title", "")
                if "CVE-" in title:
                    # Extrai CVE ID do título
                    import re
                    cve_match = re.search(r'CVE-\d{4}-\d{4,7}', title)
                    cve_id = cve_match.group(0) if cve_match else f"VULDB-{entry.get('id', 'UNKNOWN')}"
                    
                    cve_data = {
                        "id": cve_id,
                        "title": title,
                        "description": entry.get("summary", ""),
                        "published": entry.get("published", ""),
                        "cvss": None,
                        "severity": "MEDIUM",
                        "references": [entry.get("link", "")],
                        "source": self.name
                    }
                    cves.append(cve_data)
            
            return cves
        except Exception as e:
            print(f"[{self.name}] Erro no RSS: {e}")
            return []
    
    def _cvss_to_severity(self, cvss_score):
        """Converte CVSS score para severidade"""
        if not cvss_score:
            return "UNKNOWN"
        
        try:
            score = float(cvss_score)
            if score >= 9.0:
                return "CRITICAL"
            elif score >= 7.0:
                return "HIGH"
            elif score >= 4.0:
                return "MEDIUM"
            else:
                return "LOW"
        except:
            return "UNKNOWN"