from .base_collector import BaseCollector
from datetime import datetime, timedelta
import feedparser
import requests
import os

class RedHatSecurityCollector(BaseCollector):
    def __init__(self):
        super().__init__("Red Hat Security", rate_limit_delay=1.0)
        self.rss_url = "https://access.redhat.com/security/data/oval/com.redhat.rhsa-all.xml.bz2"
        # Usando RSS mais simples
        self.simple_rss = "https://access.redhat.com/security/security-updates/rss.xml"
    
    def collect_cves(self):
        """Coleta alertas de segurança do Red Hat"""
        try:
            feed = feedparser.parse(self.simple_rss)
            cves = []
            
            for entry in feed.entries[:10]:
                cve_data = {
                    "id": f"RHSA-{entry.get('id', 'UNKNOWN')}",
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