from .base_collector import BaseCollector
from datetime import datetime, timedelta
import feedparser
import requests
import os

class CISACollector(BaseCollector):
    def __init__(self):
        super().__init__("CISA", rate_limit_delay=1.0)
        self.rss_url = "https://www.cisa.gov/cybersecurity-advisories/all.xml"
    
    def collect_cves(self):
        """Coleta alertas do CISA"""
        try:
            feed = feedparser.parse(self.rss_url)
            cves = []
            
            for entry in feed.entries[:20]:  # Últimas 20
                cve_data = {
                    "id": entry.get("id", "CISA-UNKNOWN"),
                    "title": entry.get("title", ""),
                    "description": entry.get("summary", ""),
                    "published": entry.get("published", ""),
                    "cvss": None,
                    "severity": "HIGH",  # CISA geralmente publica coisas importantes
                    "references": [entry.get("link", "")],
                    "source": self.name
                }
                cves.append(cve_data)
            
            return cves
        except Exception as e:
            print(f"[{self.name}] Erro: {e}")
            return []