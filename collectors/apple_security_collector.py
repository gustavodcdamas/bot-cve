from .base_collector import BaseCollector
from datetime import datetime, timedelta
import feedparser
import requests
import os

class AppleSecurityCollector(BaseCollector):
    def __init__(self):
        super().__init__("Apple Security", rate_limit_delay=2.0)
        self.security_url = "https://support.apple.com/en-us/HT201222/rss"
    
    def collect_cves(self):
        """Coleta alertas de segurança da Apple"""
        try:
            # Apple não tem RSS, vamos fazer scraping básico da página de security updates
            response = self.safe_request(self.security_url)
            if not response:
                return []
            
            cves = []
            content = response.text
            
            # Procura por padrões de CVE na página
            cve_pattern = r'CVE-\d{4}-\d{4,7}'
            cve_matches = re.findall(cve_pattern, content)
            
            # Procura por títulos de updates
            title_pattern = r'<h3[^>]*>([^<]*(?:iOS|macOS|watchOS|tvOS)[^<]*)</h3>'
            title_matches = re.findall(title_pattern, content, re.IGNORECASE)
            
            # Combina CVEs encontradas com títulos
            for i, cve_id in enumerate(set(cve_matches[:10])):  # Últimas 10 únicas
                title = title_matches[i] if i < len(title_matches) else f"Apple Security Update"
                
                cve_data = {
                    "id": cve_id,
                    "title": title,
                    "description": f"Apple security update containing {cve_id}",
                    "published": "",  # Apple não fornece data facilmente
                    "cvss": None,
                    "severity": "MEDIUM",  # Apple updates são geralmente importantes
                    "references": [self.security_url],
                    "source": self.name
                }
                cves.append(cve_data)
            
            return cves
        except Exception as e:
            print(f"[{self.name}] Erro: {e}")
            return []