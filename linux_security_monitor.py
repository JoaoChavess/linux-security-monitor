#!/usr/bin/env python3
"""
Linux Security Monitor
-----------------------
Script de monitoramento de segurança para sistemas Linux, com foco em
sinais que um Analista SOC observaria em um ambiente real:

  1. Tentativas de login SSH falhas (possível força bruta)
  2. Criação de novos usuários no sistema
  3. Uso do comando sudo (elevação de privilégio)
  4. Portas de rede em escuta e identificação de processos anômalos
  5. Alertas automáticos via Webhook (Discord/Slack)

Autor: João Victor Chaves
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
import urllib.error
from collections import Counter
from datetime import datetime

AUTH_LOG_PATHS = ["/var/log/auth.log", "/var/log/secure"]
FAILED_LOGIN_THRESHOLD = 5  # alerta se o mesmo IP falhar N vezes ou mais

SUSPICIOUS_PROCESS_NAMES = {
    "nc", "ncat", "netcat", "socat", "python", "python3",
    "perl", "ruby", "php", "bash", "sh", "zsh"
}
KNOWN_STANDARD_PORTS = {22, 53, 80, 443}


def send_webhook_alert(webhook_url, message, severity="CRITICAL"):
    """Envia notificação via Webhook usando apenas a biblioteca padrão urllib."""
    if not webhook_url:
        return

    formatted_message = f"**[{severity}] Alerta de Segurança - Linux Monitor**\n```\n{message}\n```"
    payload = {"content": formatted_message}
    data = json.dumps(payload).encode('utf-8')
    
    req = urllib.request.Request(
        webhook_url, 
        data=data, 
        headers={
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' # Disfarce para não ser bloqueado
        },
        method='POST'
    )

    try:
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        # Silencioso em caso de falha de rede contínua para não sujar o log da tela
        pass


def find_auth_log():
    """Localiza o arquivo de log de autenticação disponível no sistema."""
    for path in AUTH_LOG_PATHS:
        if os.path.isfile(path):
            return path
    return None


def read_log_lines(path, max_lines=5000):
    """Lê as últimas N linhas do log."""
    try:
        with open(path, "r", errors="ignore") as f:
            lines = f.readlines()
        return lines[-max_lines:]
    except PermissionError:
        print(f"[!] Sem permissão para ler {path}. Rode com sudo.")
        return []
    except FileNotFoundError:
        return []


def check_failed_logins(lines):
    """Procura por linhas de falha de autenticação SSH."""
    pattern = re.compile(r"Failed password for(?: invalid user)? \S+ from (\d{1,3}(?:\.\d{1,3}){3})")
    ip_counter = Counter()

    for line in lines:
        match = pattern.search(line)
        if match:
            ip_counter[match.group(1)] += 1

    suspicious = {ip: count for ip, count in ip_counter.items() if count >= FAILED_LOGIN_THRESHOLD}
    return ip_counter, suspicious


def check_new_users(lines):
    """Detecta criação de novos usuários (comando useradd registrado no log)."""
    pattern = re.compile(r"new user: name=(\S+),")
    found = []
    for line in lines:
        match = pattern.search(line)
        if match:
            found.append({"user": match.group(1), "raw_log": line.strip()})
    return found


def check_sudo_usage(lines):
    """Lista comandos executados via sudo — útil para auditar elevação de privilégio."""
    pattern = re.compile(r"(\S+) : .*COMMAND=(.+)")
    found = []
    for line in lines:
        match = pattern.search(line)
        if match:
            found.append({"user": match.group(1), "command": match.group(2).strip()})
    return found


def parse_address_and_port(addr_str):
    """Trata múltiplos formatos de IP e porta retornados pelo ss."""
    addr_str = addr_str.strip()
    match_ipv6 = re.match(r"^\[(?P<ip>.*)\]:(?P<port>\d+)$", addr_str)
    if match_ipv6:
        return match_ipv6.group("ip"), int(match_ipv6.group("port"))

    if ":" in addr_str:
        ip_part, port_part = addr_str.rsplit(":", 1)
        if ip_part in ("*", ""):
            ip_part = "0.0.0.0"
        try:
            return ip_part, int(port_part)
        except ValueError:
            return ip_part, None

    return addr_str, None


def check_listening_ports_structured():
    """Executa 'ss -tulnp' e sinaliza processos suspeitos."""
    try:
        raw_output = subprocess.run(["ss", "-tulnp"], capture_output=True, text=True, timeout=5, check=True).stdout
    except Exception as e:
        return {"error": f"Falha ao executar ss: {e}", "listeners": [], "alerts": []}

    lines = raw_output.strip().splitlines()
    if not lines:
        return {"error": "Nenhuma saída", "listeners": [], "alerts": []}

    proc_pattern = re.compile(r'users:\(\("(?P<name>[^"]+)",(?:pid=(?P<pid>\d+))?')
    listeners, alerts = [], []

    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 5: continue

        proto = parts[0].lower()
        ip, port = parse_address_and_port(parts[4])
        if port is None: continue

        process_name, pid = "unknown", None
        users_meta = " ".join(parts[5:]) if len(parts) > 5 else ""
        proc_match = proc_pattern.search(users_meta)

        if proc_match:
            process_name = proc_match.group("name")
            pid = int(proc_match.group("pid")) if proc_match.group("pid") else None

        is_wildcard = ip in ("0.0.0.0", "::", "[::]")

        listener_entry = {
            "protocol": proto, "bind_ip": ip, "port": port,
            "is_public_interface": is_wildcard, "process_name": process_name, "pid": pid
        }
        listeners.append(listener_entry)

        if process_name.lower() in SUSPICIOUS_PROCESS_NAMES:
            alerts.append({
                "severity": "CRITICAL",
                "message": f"Processo suspeito '{process_name}' (PID: {pid}) escutando em {ip}:{port}"
            })
        elif is_wildcard and port not in KNOWN_STANDARD_PORTS:
            alerts.append({
                "severity": "MEDIUM",
                "message": f"Porta não padrão {port} aberta em 0.0.0.0/:: por '{process_name}'"
            })

    return {"listeners": listeners, "alerts": alerts}


def run_scan():
    """Executa uma varredura completa e monta o relatório final."""
    report = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "auth_log_used": None,
        "failed_logins": {},
        "brute_force_suspects": {},
        "new_users": [],
        "sudo_usage": [],
        "listening_ports": [],
        "port_alerts": [],
    }

    log_path = find_auth_log()
    report["auth_log_used"] = log_path

    if log_path:
        lines = read_log_lines(log_path)
        ip_counter, suspicious = check_failed_logins(lines)
        report["failed_logins"] = dict(ip_counter)
        report["brute_force_suspects"] = suspicious
        report["new_users"] = check_new_users(lines)
        report["sudo_usage"] = check_sudo_usage(lines)
    else:
        print("[!] Nenhum log de autenticação encontrado (auth.log / secure).")

    ports_data = check_listening_ports_structured()
    report["listening_ports"] = ports_data.get("listeners", [])
    report["port_alerts"] = ports_data.get("alerts", [])

    return report


def print_human_report(report):
    """Imprime o relatório de forma legível no terminal."""
    print("=" * 60)
    print(f" Linux Security Monitor — {report['timestamp']}")
    print("=" * 60)

    print(f"\n[Log usado] {report['auth_log_used'] or 'nenhum encontrado'}")

    print("\n[Tentativas de login falhas por IP]")
    if report["failed_logins"]:
        for ip, count in sorted(report["failed_logins"].items(), key=lambda x: -x[1]):
            flag = " <-- SUSPEITO (possível força bruta)" if ip in report["brute_force_suspects"] else ""
            print(f"  {ip}: {count} tentativa(s){flag}")
    else:
        print("  Nenhuma tentativa de login falha registrada.")

    print("\n[Novos usuários criados]")
    if report["new_users"]:
        for u in report["new_users"]:
            print(f"  + usuário criado: {u['user']}")
    else:
        print("  Nenhum novo usuário detectado.")

    print("\n[Uso de sudo (elevação de privilégio)]")
    if report["sudo_usage"]:
        for entry in report["sudo_usage"][-10:]:
            print(f"  {entry['user']} executou: {entry['command']}")
    else:
        print("  Nenhum uso de sudo registrado.")

    print("\n[Portas em Escuta e Alertas de Rede]")
    if report.get("port_alerts"):
        for alert in report["port_alerts"]:
            print(f"  [!][{alert['severity']}] {alert['message']}")
    else:
        print("  [OK] Nenhum processo suspeito na rede.")

    print("\n" + "=" * 60)
    has_issues = bool(report["brute_force_suspects"] or report.get("port_alerts"))
    if has_issues:
        print("[ALERTA GERAL] Anomalias críticas detectadas no host — verificar detalhes acima.")
    else:
        print("[OK GERAL] Nenhum indício crítico detectado nesta varredura.")
    print("=" * 60)


def process_webhook_alerts(report, webhook_url):
    """Lê o relatório e dispara os alertas críticos para o Discord."""
    if not webhook_url: 
        return

    if report.get("brute_force_suspects"):
        ips = ", ".join(report["brute_force_suspects"].keys())
        msg = f"Possível ataque de força bruta SSH detectado.\nIP(s) ofensores: {ips}"
        send_webhook_alert(webhook_url, msg, severity="CRITICAL")

    if report.get("port_alerts"):
        for alert in report["port_alerts"]:
            send_webhook_alert(webhook_url, alert["message"], severity=alert["severity"])


def save_json_report(report, path="security_report.json"):
    with open(path, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\n[+] Relatório salvo em {path}")


def main():
    parser = argparse.ArgumentParser(description="Linux Security Monitor - monitoramento SOC.")
    parser.add_argument("--once", action="store_true", help="Executa uma única varredura.")
    parser.add_argument("--watch", action="store_true", help="Executa continuamente em loop.")
    parser.add_argument("--interval", type=int, default=60, help="Intervalo em segundos (--watch).")
    parser.add_argument("--json", action="store_true", help="Salva o relatório em JSON.")
    parser.add_argument("--webhook", type=str, default=None, help="URL do Webhook do Discord/Slack")
    args = parser.parse_args()

    if not args.once and not args.watch:
        args.once = True

    if args.webhook:
        send_webhook_alert(args.webhook, "🟢 Linux Security Monitor iniciado.", severity="INFO")

    if args.watch:
        print(f"[*] Monitoramento contínuo iniciado (intervalo: {args.interval}s). Ctrl+C para parar.\n")
        try:
            while True:
                report = run_scan()
                print_human_report(report)
                process_webhook_alerts(report, args.webhook)
                
                if args.json:
                    save_json_report(report)
                
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\n[*] Monitoramento interrompido.")
            sys.exit(0)
    else:
        report = run_scan()
        print_human_report(report)
        process_webhook_alerts(report, args.webhook)
        if args.json:
            save_json_report(report)

if __name__ == "__main__":
    main()
