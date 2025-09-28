from abc import ABC, abstractmethod
import time
from datetime import datetime, timedelta
import feedparser
import requests
import os

class BaseCollector(ABC):
    def __init__(self, name: str, rate_limit_delay: float = 1.0):
        self.name = name
        self.rate_limit_delay = rate_limit_delay
        self.last_request_time = 0
    
    def _rate_limit(self):
        """Rate limiting básico"""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - elapsed)
        self.last_request_time = time.time()
    
    @abstractmethod
    def collect_cves(self):
        """Coleta CVEs da fonte específica"""
        pass
    
    def safe_request(self, url: str, **kwargs):
        """Requisição com rate limiting e headers padrão"""
        self._rate_limit()
        
        # Headers padrão
        default_headers = {
            'User-Agent': 'CVE-Bot/1.0 (Security Monitoring)',
            'Accept': 'application/json, application/xml, text/xml, */*',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        }
        
        # Merge com headers customizados
        headers = kwargs.get('headers', {})
        headers = {**default_headers, **headers}
        kwargs['headers'] = headers
        
        try:
            response = requests.get(url, timeout=30, **kwargs)
            response.raise_for_status()
            return response
        except requests.exceptions.Timeout:
            print(f"[{self.name}] Timeout na requisição para {url}")
            return None
        except requests.exceptions.HTTPError as e:
            print(f"[{self.name}] Erro HTTP {e.response.status_code} para {url}")
            return None
        except requests.exceptions.RequestException as e:
            print(f"[{self.name}] Erro na requisição para {url}: {e}")
            return None