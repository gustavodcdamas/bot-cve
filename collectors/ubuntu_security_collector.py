from .base_collector import BaseCollector
from datetime import datetime, timedelta
import feedparser
import requests
import os

class UbuntuSecurityCollector(BaseCollector):
    def __init__(self):
        super().__init__("Ubuntu Security", rate_limit_delay=1.0)
        self.rss_url = "https://ubuntu.com/security/notices/rss.xml"
    
    def collect_cves(self):
        """Coleta alertas de segurança do Ubuntu"""
        try:
            feed = feedparser.parse(self.rss_url)
            cves = []
            
            for entry in feed.entries[:15]:
                cve_data = {
                    "id": f"USN-{entry.get('id', 'UNKNOWN')}",
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