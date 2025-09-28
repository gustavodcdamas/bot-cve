from .base_collector import BaseCollector
from datetime import datetime, timedelta
import feedparser
import requests
import os

class FIRSTCollector(BaseCollector):
    def __init__(self):
        super().__init__("FIRST.org", rate_limit_delay=1.0)
        self.rss_url = "https://www.first.org/rss/alerts.xml"
    
    def collect_cves(self):
        """Coleta alertas do FIRST.org"""
        try:
            feed = feedparser.parse(self.rss_url)
            cves = []
            
            for entry in feed.entries[:10]:
                title = entry.get("title", "")
                description = entry.get("summary", "")
                
                cve_data = {
                    "id": f"FIRST-{entry.get('id', 'UNKNOWN')}",
                    "title": title,
                    "description": description,
                    "published": entry.get("published", ""),
                    "cvss": None,
                    "severity": "HIGH",  # FIRST geralmente publica coisas importantes
                    "references": [entry.get("link", "")],
                    "source": self.name
                }
                cves.append(cve_data)
            
            return cves
        except Exception as e:
            print(f"[{self.name}] Erro: {e}")
            return []