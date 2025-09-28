from .base_collector import BaseCollector
from datetime import datetime, timedelta
import feedparser
import requests
import os

class CIRCLCollector(BaseCollector):
    def __init__(self):
        super().__init__("CIRCL", rate_limit_delay=1.0)
        self.api_url = "https://cve.circl.lu/api/last"
    
    def collect_cves(self):
        """Coleta CVEs do CIRCL"""
        try:
            response = self.safe_request(self.api_url)
            if not response:
                return []
            
            data = response.json()
            cves = []
            
            # CIRCL retorna lista de CVEs
            for item in data[:20]:  # Últimas 20
                cve_data = {
                    "id": item.get("id", "CIRCL-UNKNOWN"),
                    "title": item.get("summary", "")[:100] + "..." if len(item.get("summary", "")) > 100 else item.get("summary", ""),
                    "description": item.get("summary", ""),
                    "published": item.get("Published", ""),
                    "cvss": item.get("cvss"),
                    "severity": self._cvss_to_severity(item.get("cvss")),
                    "references": [f"https://cve.circl.lu/cve/{item.get('id', '')}"],
                    "source": self.name
                }
                cves.append(cve_data)
            
            return cves
        except Exception as e:
            print(f"[{self.name}] Erro: {e}")
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