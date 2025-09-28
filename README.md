# CVE Bot

Um Bot que envia CVEs catalogadas em tempo real para canais no telegram, discord e teams (ou qualquer outra plataforma que tenha webhook com um payload compatível). As CVEs são filtradas por palavras chaves, inseridas no arquivo .env na hora da configuração do bot.

Bot com total suporte a coleta via Prometheus, e alertas via Alertmanager.

## Pré requisitos

Docker desktop, ou docker engine, ou docker-compose.

## Fontes de coleta
Atualmente, o CVE Bot coleta CVEs de quase todas as fontes oficiais ou confiáveis disponíveis, segue a lista de quis são elas:

| Fonte | Implementado? |
|-------|---------------|
| Apple Security Center | ✅ |
| AWS Security Center | ✅ |
| Cert BR | ✅ |
| CERT EU | ✅ |
| Circl | ✅ |
| Cisa.gov | ✅ |
| Cve.org | ✅ |
| Debian Security Center | ✅ |
| Docker Security Center | ✅ |
| Exploit DB | ✅ |
| First.org | ✅ |
| Github Advisory Center | ✅ |
| Google Security Center | ✅ |
| Guac | ❌ |
| Microsoft Security Center | ✅ |
| Mitre.org | ✅ |
| NPM Security Center | ✅ |
| Nvd.nist.org | ✅ |
| Opencve.org | ✅ |
| Open SSF | ❌ |
| Red Hat Security Center | ✅ |
| Sigstore | ❌ |
| Slsa | ❌ |
| Snyk.io | ✅ |
| Ubuntu Security Center | ✅ |
| Vul DB | ✅ |

## Construído com

- [Docker](https://docs.docker.com/)
- [Python](https://docs.python.org/3/)
- [Bash](https://www.gnu.org/doc/doc.html)
# Configuração
## Docker

1- Rode o seguinte comando para executar o container direto pela linha de comando:

```bash
docker run -p 8080:8080 gustavodcdamas/cve_collector:latest
```

## docker-compose (recomendado para maior controle e precisão)

1- Crie um arquivo .env, e cole as informações contidas no .env.example, e preencha conforme sua necessidade (webhook do teams, webhook do discord, token do seu bot no telegram, canal que deseja que o as notificações sejam enviadas etc):

```bash
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...

TEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/...

TELEGRAM_BOT_TOKEN=123456789:ABCdefGHIjklMNOpqrsTUVwxyz
TELEGRAM_CHANNEL_ID=-10
TELEGRAM_MESSAGE_THREAD_ID=09809
```

2- Depois de preencher os dados de onde deseja receber as notificações, preencha as palavras chaves, para que o CVE Bot possa filtrar apenas CVEs relevantes para você ou sua organização, e preencha o nível de severidade que deseja receber, além do intervalo de tempo que o Bot deve verificar por novas CVEs:

```bash
CHECK_INTERVAL=3600
MAX_CVES_PER_CHECK=100
MIN_CVSS_SCORE=4.0
MIN_SEVERITY=MEDIUM

PALAVRAS_CHAVE=linux,ubuntu,aws,amazon,android,ios,react,dotnet,.NET,c,'c#',php,nestjs,docker,kubernetes,npm,nodejs,python,java,javascript
```

3- O Arquivo docker-compose final, ficará mais ou menos assim:

```yaml
services:
  cve_collector:
    container_name: cve_collector
    image: gustavodcdamas/cve_collector:latest
    mem_limit: 512M
    cpus: 0.15
    ports:
      - "8888:8888"
    restart: unless-stopped
    env_file:
      - .env
    volumes:
      - ./data:/app/data
    environment:
      - TZ=America/Sao_Paulo
    networks:
      - cve_collector_net

networks:
  cve_collector_net:
    name: cve_collector_net
```

4- O arquivo .env final, ficará mais ou menos assim após editado conforme suas necessidades:

```bash
# Configurações gerais
CHECK_INTERVAL=3600
MAX_CVES_PER_CHECK=100
MIN_CVSS_SCORE=4.0
MIN_SEVERITY=MEDIUM

# Notificações Teams
TEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/...

#Notificações Telegram
TELEGRAM_BOT_TOKEN=123456789:ABCdefGHIjklMNOpqrsTUVwxyz
TELEGRAM_CHANNEL_ID=-10
TELEGRAM_MESSAGE_THREAD_ID=09809

#Notificações Dicord
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...

#Time Zone
TZ=America/Sao_Paulo

#Filtrar por palavars chave, separe as palavras por virgula (para receber todas as cves deixe em branco)
PALAVRAS_CHAVE=linux,ubuntu,aws,amazon,android,ios,react,dotnet,.NET,c,'c#',php,nestjs,docker,kubernetes,npm,nodejs,python,java,javascript

# APIs Opcionais (deixe em branco se não tiver)
GITHUB_TOKEN=ghp_xxxxxxxxxxxx
VULDB_API_KEY=xxxxxxxxxxxxxxxx
OPENCVE_API_KEY=xxxxxxxxxxxxxxxx
```

## Contribuições

Pull requests são bem vindos. Para alguma atualização, por favor, abra uma issue antes, para que possamos discutir o que será alterado, e como será alterado.

Por favor, se assegure de fazer os devidos testes antes.

## License

[GNU General Public License v3.0](https://github.com/gustavodcdamas/bot-cve/blob/main/LICENSE)
