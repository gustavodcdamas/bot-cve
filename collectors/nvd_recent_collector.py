from .base_collector import BaseCollector
from datetime import datetime, timedelta
import feedparser
import requests
import os

class NVDRecentCollector(BaseCollector):
    def __init__(self):
        super().__init__("NVD Recent", rate_limit_delay=2.0)
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def collect_cves(self):
        """Coleta CVEs recentes do NVD (últimas 24h)"""
        # Pega CVEs das últimas 24 horas
        end_date = datetime.now()
        start_date = end_date - timedelta(days=1)
        
        params = {
            "resultsPerPage": 100,
            "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        }
        
        response = self.safe_request(self.base_url, params=params)
        if not response:
            return []
        
        try:
            data = response.json()
            cves = []
            
            for item in data.get("vulnerabilities", []):
                cve_data = item.get("cve", {})
                parsed_cve = self._parse_cve(cve_data)
                if parsed_cve:
                    cves.append(parsed_cve)
            
            return cves
        except Exception as e:
            print(f"[{self.name}] Erro: {e}")
            return []
    
    def _parse_cve(self, cve_data):
        """Converte dados do NVD para formato padrão"""
        try:
            cve_id = cve_data["id"]
            
            # Descrição
            descriptions = cve_data.get("descriptions", [])
            description = next((d["value"] for d in descriptions if d["lang"] == "en"), "N/A")
            
            # CVSS e Severidade
            cvss_score = None
            severity = "UNKNOWN"
            
            metrics = cve_data.get("metrics", {})
            if "cvssMetricV31" in metrics:
                cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                cvss_score = cvss_data["baseScore"]
                severity = cvss_data["baseSeverity"]
            elif "cvssMetricV30" in metrics:
                cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
                cvss_score = cvss_data["baseScore"]
                severity = cvss_data["baseSeverity"]
            
            return {
                "id": cve_id,
                "title": description[:100] + "..." if len(description) > 100 else description,
                "description": description,
                "published": cve_data["published"],
                "cvss": cvss_score,
                "severity": severity,
                "references": [f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
                "source": self.name
            }
        except Exception as e:
            print(f"[{self.name}] Erro ao processar CVE: {e}")
            return None