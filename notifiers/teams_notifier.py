import requests

class TeamsNotifier:
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
    
    def send_notification(self, cve_data):
        """Envia notificação para Teams"""
        message = self._create_message(cve_data)
        try:
            response = requests.post(self.webhook_url, json=message, timeout=10)
            response.raise_for_status()
            print(f"[Teams] CVE {cve_data['id']} enviada com sucesso")
        except Exception as e:
            print(f"[Teams] Erro ao enviar {cve_data['id']}: {e}")
    
    def _create_message(self, cve_data) -> dict:
        """Cria mensagem formatada para Teams"""
        color = self._get_color_by_severity(cve_data.get('severity', 'UNKNOWN'))
        
        return {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color,
            "summary": f"Nova vulnerabilidade: {cve_data['id']}",
            "sections": [{
                "activityTitle": f"🚨 **{cve_data['id']}** - {cve_data.get('severity', 'N/A')}",
                "activitySubtitle": f"Fonte: {cve_data['source']} | Publicado: {cve_data.get('published', 'N/A')}",
                "facts": [
                    {"name": "CVSS Score", "value": str(cve_data.get('cvss')) if cve_data.get('cvss') else "N/A"},
                    {"name": "Severidade", "value": cve_data.get('severity', 'N/A')},
                    {"name": "Descrição", "value": cve_data.get('description', 'N/A')[:500] + "..." if len(cve_data.get('description', '')) > 500 else cve_data.get('description', 'N/A')}
                ],
                "markdown": True
            }],
            "potentialAction": [{
                "@type": "OpenUri",
                "name": "Ver Detalhes",
                "targets": [{
                    "os": "default",
                    "uri": cve_data.get('references', [''])[0] if cve_data.get('references') else f"https://nvd.nist.gov/vuln/detail/{cve_data['id']}"
                }]
            }]
        }
    
    def _get_color_by_severity(self, severity: str) -> str:
        """Retorna cor baseada na severidade"""
        colors = {
            "CRITICAL": "FF0000",
            "HIGH": "FF6600",
            "MEDIUM": "FFCC00",
            "LOW": "00CC00"
        }
        return colors.get(severity, "808080")