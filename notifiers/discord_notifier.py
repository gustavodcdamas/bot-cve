import requests

class DiscordNotifier:
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
    
    def send_notification(self, cve_data):
        """Envia notificação para Discord"""
        embed = self._create_embed(cve_data)
        try:
            response = requests.post(
                self.webhook_url,
                json={"embeds": [embed]},
                timeout=10
            )
            response.raise_for_status()
            print(f"[Discord] CVE {cve_data['id']} enviada com sucesso")
        except Exception as e:
            print(f"[Discord] Erro ao enviar {cve_data['id']}: {e}")
    
    def _create_embed(self, cve_data) -> dict:
        """Cria embed formatado para Discord"""
        color = self._get_color_by_severity(cve_data.get('severity', 'UNKNOWN'))
        
        embed = {
            "title": f"🚨 {cve_data['id']} - {cve_data.get('severity', 'N/A')}",
            "description": cve_data.get('description', 'N/A')[:2000] + ("..." if len(cve_data.get('description', '')) > 2000 else ""),
            "color": color,
            "fields": [
                {
                    "name": "CVSS Score",
                    "value": str(cve_data.get('cvss')) if cve_data.get('cvss') else "N/A",
                    "inline": True
                },
                {
                    "name": "Fonte",
                    "value": cve_data.get('source', 'N/A'),
                    "inline": True
                },
                {
                    "name": "Publicado",
                    "value": cve_data.get('published', 'N/A'),
                    "inline": True
                }
            ],
            "footer": {
                "text": "CVE Bot - Monitoramento de Vulnerabilidades"
            }
        }
        
        if cve_data.get('references'):
            embed["url"] = cve_data['references'][0]
        
        return embed
    
    def _get_color_by_severity(self, severity: str) -> int:
        """Retorna cor em decimal baseada na severidade"""
        colors = {
            "CRITICAL": 16711680,  # Vermelho
            "HIGH": 16753920,      # Laranja
            "MEDIUM": 16776960,    # Amarelo
            "LOW": 65280          # Verde
        }
        return colors.get(severity, 8421504)  # Cinza