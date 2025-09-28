from .base_collector import BaseCollector
from datetime import datetime, timedelta
import feedparser
import requests
import os

class CERTEUCollector(BaseCollector):
    def __init__(self):
        super().__init__("CERT-EU", rate_limit_delay=1.0)
        self.rss_url = "https://cert.europa.eu/cert/newsletter/en/latest_SecurityBulletins_.rss"
    
    def collect_cves(self):
        """Coleta alertas do CERT-EU"""
        try:
            feed = feedparser.parse(self.rss_url)
            cves = []
            
            for entry in feed.entries[:10]:
                cve_data = {
                    "id": f"CERT-EU-{entry.get('id', 'UNKNOWN')}",
                    "title": entry.get("title", ""),
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
            print(f"[{self.name}] Erro: {e}")
            return []