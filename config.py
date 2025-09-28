import os
from dotenv import load_dotenv

load_dotenv()

# Configurações gerais
CHECK_INTERVAL = int(os.getenv('CHECK_INTERVAL', 3600))
MAX_CVES_PER_CHECK = int(os.getenv('MAX_CVES_PER_CHECK', 100))
MIN_CVSS_SCORE = float(os.getenv('MIN_CVSS_SCORE', 4.0))
MIN_SEVERITY = os.getenv('MIN_SEVERITY', 'MEDIUM')

# Palavras-chave (separadas por vírgula)
PALAVRAS_CHAVE_STR = os.getenv('PALAVRAS_CHAVE', '')
KEYWORDS = [kw.strip() for kw in PALAVRAS_CHAVE_STR.split(',') if kw.strip()] if PALAVRAS_CHAVE_STR else []

# Configurações de notificação do Teams
TEAMS_WEBHOOK_URL = os.getenv('TEAMS_WEBHOOK_URL')

# Configurações de notificação do Telegram
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
TELEGRAM_CHANNEL_ID = os.getenv('TELEGRAM_CHANNEL_ID')
TELEGRAM_MESSAGE_THREAD_ID = os.getenv('TELEGRAM_MESSAGE_THREAD_ID')

# Configurações de notificação do Discord
DISCORD_WEBHOOK_URL = os.getenv('DISCORD_WEBHOOK_URL')