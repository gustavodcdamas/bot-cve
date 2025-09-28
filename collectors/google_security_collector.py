from .base_collector import BaseCollector
from datetime import datetime, timedelta
import feedparser
import requests
import os

class GoogleSecurityCollector(BaseCollector):
    def __init__(self):
        super().__init__("Google Security", rate_limit_delay=1.0)
        self.rss_url = "https://security.googleblog.com/feeds/posts/default"
    
    def collect_cves(self):
        """Coleta alertas do Google Security Blog"""
        try:
            feed = feedparser.parse(self.rss_url)
            cves = []
            
            for entry in feed.entries[:10]:
                title = entry.get("title", "")
                # Filtra posts relacionados a vulnerabilidades
                if any(keyword in title.lower() for keyword in ["vulnerability", "security", "cve", "patch", "update"]):
                    cve_data = {
                        "id": f"GOOGLE-SEC-{entry.get('id', 'UNKNOWN')}",
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
            print(f"[{self.name}] Erro: {e}")
            return []