from .base_collector import BaseCollector
from datetime import datetime, timedelta
import feedparser
import requests
import os

class MicrosoftSecurityCollector(BaseCollector):
    def __init__(self):
        super().__init__("Microsoft Security", rate_limit_delay=1.0)
        self.rss_url = "https://api.msrc.microsoft.com/cvrf/v2.0/updates"
        # Usando RSS mais simples
        self.simple_rss = "https://msrc.microsoft.com/blog/feed/"
    
    def collect_cves(self):
        """Coleta alertas de segurança da Microsoft"""
        try:
            feed = feedparser.parse(self.simple_rss)
            cves = []
            
            for entry in feed.entries[:10]:
                title = entry.get("title", "")
                # Filtra apenas posts relacionados a segurança
                if any(keyword in title.lower() for keyword in ["security", "vulnerability", "update", "patch"]):
                    cve_data = {
                        "id": f"MSRC-{entry.get('id', 'UNKNOWN')}",
                        "title": title,
                        "description": entry.get("summary", ""),
                        "published": entry.get("published", ""),
                        "cvss": None,
                        "severity": "HIGH",  # Microsoft geralmente publica coisas importantes
                        "references": [entry.get("link", "")],
                        "source": self.name
                    }
                    cves.append(cve_data)
            
            return cves
        except Exception as e:
            print(f"[{self.name}] Erro: {e}")
            return []