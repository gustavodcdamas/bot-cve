from .base_collector import BaseCollector
from datetime import datetime, timedelta
import feedparser
import requests
import os

class CERTBRCollector(BaseCollector):
    def __init__(self):
        super().__init__("CERT.br", rate_limit_delay=1.0)
        self.rss_url = "https://www.cert.br/feed/"
    
    def collect_cves(self):
        """Coleta alertas do CERT.br"""
        try:
            feed = feedparser.parse(self.rss_url)
            cves = []
            
            for entry in feed.entries[:10]:
                cve_data = {
                    "id": f"CERT-BR-{entry.get('id', 'UNKNOWN')}",
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