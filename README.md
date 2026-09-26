# Linux Security Monitor

Script em Python para monitoramento básico de segurança em sistemas Linux,
simulando tarefas que um **Analista SOC / Blue Team** realiza no dia a dia
para detectar atividade suspeita em um servidor.

## O que o script monitora

| Item monitorado | Por que importa para segurança |
|---|---|
| **Tentativas de login SSH falhas** | Muitas falhas do mesmo IP indicam possível ataque de força bruta ou password spraying |
| **Criação de novos usuários** | Um usuário criado sem autorização pode indicar comprometimento do sistema (persistência do atacante) |
| **Uso do comando `sudo`** | Elevação de privilégio é um dos passos críticos em qualquer ataque — auditar isso é essencial |
| **Portas de rede em escuta** | Toda porta aberta é uma superfície de ataque; portas inesperadas podem indicar backdoor ou serviço mal configurado |

## Como funciona

O script lê o log de autenticação do sistema (`/var/log/auth.log` no
Ubuntu/Debian, ou `/var/log/secure` no CentOS/RHEL), procura por padrões
específicos usando expressões regulares, e gera um relatório destacando
qualquer atividade que ultrapasse o limite considerado normal (por padrão,
5 ou mais tentativas de login falhas do mesmo IP disparam um alerta).

## Como usar

```bash
# Varredura única (mostra o relatório uma vez e encerra)
sudo python3 linux_security_monitor.py --once

# Monitoramento contínuo, verificando a cada 30 segundos
sudo python3 linux_security_monitor.py --watch --interval 30

# Salvar também um relatório em JSON (útil para integrar com outras ferramentas)
sudo python3 linux_security_monitor.py --once --json
```

> **Por que `sudo`?** O log de autenticação (`/var/log/auth.log`) normalmente
> só pode ser lido por usuários com privilégio elevado, por conter informação
> sensível sobre logins do sistema.

## Exemplo de saída

```
============================================================
 Linux Security Monitor — 2026-09-26T14:32:10
============================================================

[Log usado] /var/log/auth.log

[Tentativas de login falhas por IP]
  203.0.113.45: 12 tentativa(s) <-- SUSPEITO (possível força bruta)
  198.51.100.9: 2 tentativa(s)

[Novos usuários criados]
  Nenhum novo usuário detectado no período analisado.

[Uso de sudo (elevação de privilégio)]
  joao executou: /usr/bin/apt update

[Portas em escuta (superfície de ataque)]
  tcp   LISTEN  0  128  0.0.0.0:22   0.0.0.0:*  users:(("sshd",pid=812,fd=3))

============================================================
[ALERTA] Há IPs com múltiplas falhas de login — investigar possível força bruta.
============================================================
```

## Possíveis melhorias futuras

- Enviar alerta automático por e-mail/webhook quando detectar força bruta
- Persistir histórico em banco de dados (SQLite) para análise de tendência
- Adicionar verificação de integridade de arquivos críticos (`/etc/passwd`, `/etc/shadow`)
- Integração com um SIEM (ex: enviar eventos para o Wazuh ou Splunk)

## Tecnologias usadas

- Python 3 (biblioteca padrão apenas — sem dependências externas)
- Regex para parsing de logs
- `ss` / `netstat` para levantamento de portas de rede

---

Projeto desenvolvido como parte dos estudos em Segurança Cibernética (Blue Team / SOC).
