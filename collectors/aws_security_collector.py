from .base_collector import BaseCollector
from datetime import datetime, timedelta
import feedparser
import requests
import os

class AWSSecurityCollector(BaseCollector):
    def __init__(self):
        super().__init__("AWS Security", rate_limit_delay=1.0)
        self.rss_url = "https://aws.amazon.com/security/security-bulletins/rss/"
    
    def collect_cves(self):
        """Coleta boletins de segurança da AWS"""
        try:
            feed = feedparser.parse(self.rss_url)
            cves = []
            
            for entry in feed.entries[:10]:
                cve_data = {
                    "id": f"AWS-SEC-{entry.get('id', 'UNKNOWN')}",
                    "title": entry.get("title", ""),
                    "description": entry.get("summary", ""),
                    "published": entry.get("published", ""),
                    "cvss": None,
                    "severity": "HIGH",  # AWS security bulletins são importantes
                    "references": [entry.get("link", "")],
                    "source": self.name
                }
                cves.append(cve_data)
            
            return cves
        except Exception as e:
            print(f"[{self.name}] Erro: {e}")
            return []