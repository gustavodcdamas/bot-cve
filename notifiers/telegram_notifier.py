import requests
import os
from datetime import datetime

class TelegramNotifier:
    def __init__(self, bot_token: str, channel_id: str, thread_id: str = None):
        self.bot_token = bot_token
        self.channel_id = channel_id
        self.thread_id = thread_id  # NOVO
        self.base_url = f"https://api.telegram.org/bot{bot_token}"
    
    def send_notification(self, cve_data):
        """Envia notificação para Telegram"""
        message = self._create_message(cve_data)
        
        payload = {
            "chat_id": self.channel_id,
            "text": message,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True
        }
        
        # Adiciona thread_id se especificado
        if self.thread_id:
            payload["message_thread_id"] = self.thread_id
        
        try:
            response = requests.post(
                f"{self.base_url}/sendMessage",
                json=payload,
                timeout=10
            )
            response.raise_for_status()
            print(f"[Telegram] CVE {cve_data['id']} enviada com sucesso")
        except Exception as e:
            print(f"[Telegram] Erro ao enviar {cve_data['id']}: {e}")
    
    def _create_message(self, cve_data) -> str:
        """Cria mensagem formatada para Telegram"""
        severity_emoji = {
            "CRITICAL": "🔴",
            "HIGH": "🟠", 
            "MEDIUM": "🟡",
            "LOW": "🟢"
        }
        
        emoji = severity_emoji.get(cve_data.get('severity', ''), "⚪")
        
        message = f"""
{emoji} *Nova Vulnerabilidade Detectada!*

*CVE ID:* `{cve_data['id']}`
*Severidade:* {cve_data.get('severity', 'N/A')}
*CVSS Score:* {cve_data.get('cvss', 'N/A')}
*Publicado:* {cve_data['published']}

*Descrição:*
{cve_data['description'][:800]}{'...' if len(cve_data['description']) > 800 else ''}

[🔗 Ver Detalhes]({cve_data['references'][0] if cve_data.get('references') else f'https://nvd.nist.gov/vuln/detail/{cve_data["id"]}'})
        """.strip()
        
        return message