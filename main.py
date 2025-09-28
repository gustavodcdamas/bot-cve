import os
import time
import json
from datetime import datetime
from prometheus_client import start_http_server, Counter, Gauge
from dotenv import load_dotenv

# Importa notificadores
from notifiers.telegram_notifier import TelegramNotifier
from notifiers.teams_notifier import TeamsNotifier
from notifiers.discord_notifier import DiscordNotifier

# Importa coletores
from collectors.nvd_collector import NVDCollector
from collectors.cisa_collector import CISACollector
from collectors.cert_br_collector import CERTBRCollector
from collectors.exploit_db_collector import ExploitDBCollector
from collectors.github_advisory_collector import GitHubAdvisoryCollector
from collectors.vuldb_collector import VulDBCollector
from collectors.ubuntu_security_collector import UbuntuSecurityCollector
from collectors.redhat_security_collector import RedHatSecurityCollector
from collectors.circl_collector import CIRCLCollector
from collectors.cert_eu_collector import CERTEUCollector
from collectors.microsoft_security_collector import MicrosoftSecurityCollector
from collectors.google_security_collector import GoogleSecurityCollector
from collectors.aws_security_collector import AWSSecurityCollector
from collectors.npm_security_collector import NPMSecurityCollector
from collectors.docker_security_collector import DockerSecurityCollector
from collectors.debian_collector import DebianCollector
from collectors.apple_security_collector import AppleSecurityCollector
from collectors.mitre_collector import MITRECollector
from collectors.opencve_collector import OpenCVECollector

load_dotenv()

# Configurações
CHECK_INTERVAL = int(os.getenv('CHECK_INTERVAL', 3600))
MIN_CVSS_SCORE = float(os.getenv('MIN_CVSS_SCORE', 4.0))
MIN_SEVERITY = os.getenv('MIN_SEVERITY', 'MEDIUM')

# Palavras-chave
PALAVRAS_CHAVE_STR = os.getenv('PALAVRAS_CHAVE', '')
KEYWORDS = [kw.strip().lower() for kw in PALAVRAS_CHAVE_STR.split(',') if kw.strip()] if PALAVRAS_CHAVE_STR else []

# Configurações de notificação
TEAMS_WEBHOOK_URL = os.getenv('TEAMS_WEBHOOK_URL')
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
TELEGRAM_CHANNEL_ID = os.getenv('TELEGRAM_CHANNEL_ID')
TELEGRAM_MESSAGE_THREAD_ID = os.getenv('TELEGRAM_MESSAGE_THREAD_ID')
DISCORD_WEBHOOK_URL = os.getenv('DISCORD_WEBHOOK_URL')

# APIs opcionais
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
VULDB_API_KEY = os.getenv('VULDB_API_KEY')
OPENCVE_API_KEY = os.getenv('OPENCVE_API_KEY')

# Métricas Prometheus
cve_processed_total = Counter('cve_processed_total', 'Total de CVEs processadas', ['source', 'severity'])
cve_notifications_sent = Counter('cve_notifications_sent', 'Notificações enviadas', ['platform'])
cve_last_check = Gauge('cve_last_check_timestamp', 'Timestamp da última verificação')
cve_collection_errors = Counter('cve_collection_errors_total', 'Erros na coleta de CVEs', ['source'])

# Armazenamento das CVEs processadas
PROCESSED_FILE = '/app/data/processed_cves.json'

def load_processed_cves():
    """Carrega CVEs já processadas"""
    try:
        if os.path.exists(PROCESSED_FILE):
            with open(PROCESSED_FILE, 'r') as f:
                return set(json.load(f))
    except Exception as e:
        print(f"Erro ao carregar CVEs processadas: {e}")
    return set()

def save_processed_cves(processed_cves):
    """Salva CVEs processadas"""
    try:
        os.makedirs(os.path.dirname(PROCESSED_FILE), exist_ok=True)
        with open(PROCESSED_FILE, 'w') as f:
            json.dump(list(processed_cves), f)
    except Exception as e:
        print(f"Erro ao salvar CVEs processadas: {e}")

def matches_keywords(text, keywords):
    """Verifica se o texto contém alguma palavra-chave"""
    if not keywords:
        return True
    
    text_lower = text.lower()
    return any(keyword in text_lower for keyword in keywords)

def is_relevant_cve(cve_data, keywords, min_cvss, min_severity):
    """Verifica se a CVE é relevante baseada nos critérios"""
    # Verifica palavras-chave
    search_text = f"{cve_data.get('description', '')} {cve_data.get('title', '')}"
    if not matches_keywords(search_text, keywords):
        return False
    
    # Verifica CVSS score
    cvss = cve_data.get('cvss')
    if cvss and cvss < min_cvss:
        return False
    
    # Verifica severidade
    severity_order = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
    cve_severity = cve_data.get('severity', 'UNKNOWN')
    if severity_order.get(cve_severity, 0) < severity_order.get(min_severity, 0):
        return False
    
    return True

class CVEBot:
    def __init__(self):
        self.processed_cves = load_processed_cves()
        
        # Inicializa coletores que funcionam
        self.collectors = [
            # Fontes oficiais governamentais
            NVDCollector(),                    # ✅ Funciona
            CISACollector(),                   # ✅ Funciona
            CERTBRCollector(),                 # ✅ Funciona
            CERTEUCollector(),                 # ✅ Funciona
            
            # Fontes de vulnerabilidades
            ExploitDBCollector(),              # ✅ Funciona
            VulDBCollector(),                  # ✅ Funciona (RSS)
            CIRCLCollector(),                  # ✅ Funciona
            
            # Plataformas e repositórios
            GitHubAdvisoryCollector(),         # ✅ Funciona
            NPMSecurityCollector(),            # ✅ Funciona
            
            # Fornecedores específicos
            MicrosoftSecurityCollector(),      # ✅ Funciona
            GoogleSecurityCollector(),         # ✅ Funciona
            AWSSecurityCollector(),            # ✅ Funciona
            DockerSecurityCollector(),         # ✅ Funciona
            
            # Distribuições Linux
            UbuntuSecurityCollector(),         # ✅ Funciona
            RedHatSecurityCollector(),         # ✅ Funciona
            DebianCollector(),                 # ⚠️ Vamos melhorar
            
            # Outros
            AppleSecurityCollector(),          # ⚠️ Vamos implementar
            # MITRECollector(),                # ❌ API complexa, desabilitado por enquanto
            OpenCVECollector(),              # ❌ Pode precisar de API key
        ]
        
        # Inicializa notificadores
        self.notifiers = []
        
        if TEAMS_WEBHOOK_URL:
            self.notifiers.append(TeamsNotifier(TEAMS_WEBHOOK_URL))
        
        if TELEGRAM_BOT_TOKEN and TELEGRAM_CHANNEL_ID:
            self.notifiers.append(TelegramNotifier(
                TELEGRAM_BOT_TOKEN, 
                TELEGRAM_CHANNEL_ID, 
                TELEGRAM_MESSAGE_THREAD_ID
            ))
        
        if DISCORD_WEBHOOK_URL:
            self.notifiers.append(DiscordNotifier(DISCORD_WEBHOOK_URL))
    
    def collect_new_cves(self):
        """Coleta novas CVEs de todas as fontes"""
        all_new_cves = []
        
        for collector in self.collectors:
            print(f"Coletando CVEs de {collector.name}...")
            
            try:
                cves = collector.collect_cves()
                
                # Filtra CVEs já processadas
                new_cves = [cve for cve in cves if cve.get('id') and cve['id'] not in self.processed_cves]
                
                # Filtra por relevância
                relevant_cves = [
                    cve for cve in new_cves 
                    if is_relevant_cve(cve, KEYWORDS, MIN_CVSS_SCORE, MIN_SEVERITY)
                ]
                
                all_new_cves.extend(relevant_cves)
                
                # Atualiza métricas
                for cve in relevant_cves:
                    cve_processed_total.labels(
                        source=cve.get('source', 'UNKNOWN'), 
                        severity=cve.get('severity', 'UNKNOWN')
                    ).inc()
                
                print(f"[{collector.name}] {len(relevant_cves)} CVEs relevantes encontradas")
                
            except Exception as e:
                print(f"Erro ao coletar de {collector.name}: {e}")
                cve_collection_errors.labels(source=collector.name).inc()
        
        return all_new_cves
    
    def send_notifications(self, cves):
        """Envia notificações para todas as plataformas"""
        if not cves:
            return
        
        for notifier in self.notifiers:
            try:
                for cve in cves:
                    notifier.send_notification(cve)
                    time.sleep(1)  # Evita spam
                
                cve_notifications_sent.labels(
                    platform=notifier.__class__.__name__
                ).inc(len(cves))
                
            except Exception as e:
                print(f"Erro ao enviar notificação via {notifier.__class__.__name__}: {e}")
    
    def run(self):
        """Loop principal do bot"""
        print("🚀 CVE Bot iniciado!")
        print(f"Verificando a cada {CHECK_INTERVAL} segundos")
        print(f"Palavras-chave: {', '.join(KEYWORDS) if KEYWORDS else 'TODAS'}")
        print(f"Severidade mínima: {MIN_SEVERITY}")
        print(f"CVSS mínimo: {MIN_CVSS_SCORE}")
        print(f"Coletores ativos: {len(self.collectors)}")
        print(f"Notificadores ativos: {len(self.notifiers)}")
        
        # Lista coletores
        print("\n📡 Fontes de CVE ativas:")
        for collector in self.collectors:
            print(f"  - {collector.name}")
        
        while True:
            try:
                print(f"\n{datetime.now()} - Iniciando verificação de CVEs...")
                
                # Coleta novas CVEs
                new_cves = self.collect_new_cves()
                
                if new_cves:
                    print(f"📢 {len(new_cves)} novas CVEs relevantes encontradas!")
                    
                    # Envia notificações
                    self.send_notifications(new_cves)
                    
                    # Marca como processadas
                    for cve in new_cves:
                        if cve.get('id'):
                            self.processed_cves.add(cve['id'])
                    
                    # Salva no arquivo
                    save_processed_cves(self.processed_cves)
                    
                    print("✅ Notificações enviadas e CVEs marcadas como processadas")
                else:
                    print("ℹ️ Nenhuma CVE nova relevante encontrada")
                
                # Atualiza métrica de última verificação
                cve_last_check.set_to_current_time()
                
                print(f"⏰ Próxima verificação em {CHECK_INTERVAL} segundos")
                time.sleep(CHECK_INTERVAL)
                
            except KeyboardInterrupt:
                print("\n🛑 Bot interrompido pelo usuário")
                break
            except Exception as e:
                print(f"❌ Erro inesperado: {e}")
                time.sleep(60)

if __name__ == "__main__":
    # Inicia servidor de métricas Prometheus
    start_http_server(8888)
    print("📊 Servidor de métricas iniciado na porta 8888")
    
    # Inicia o bot
    bot = CVEBot()
    bot.run()