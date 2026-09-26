#!/usr/bin/env python3
"""
Linux Security Monitor
-----------------------
Script de monitoramento de segurança para sistemas Linux, com foco em
sinais que um Analista SOC observaria em um ambiente real:

  1. Tentativas de login SSH falhas (possível força bruta)
  2. Criação de novos usuários no sistema
  3. Uso do comando sudo (elevação de privilégio)
  4. Portas de rede em escuta (superfície de ataque exposta)

O script lê os logs padrão do sistema (/var/log/auth.log ou
/var/log/secure, dependendo da distro) e gera um relatório em texto
e em JSON, além de imprimir alertas no terminal em tempo real.

Uso:
    sudo python3 linux_security_monitor.py --once
    sudo python3 linux_security_monitor.py --watch --interval 30

Autor: João Victor Chaves
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime

AUTH_LOG_PATHS = ["/var/log/auth.log", "/var/log/secure"]

FAILED_LOGIN_THRESHOLD = 5  # alerta se o mesmo IP falhar N vezes ou mais


def find_auth_log():
    """Localiza o arquivo de log de autenticação disponível no sistema."""
    for path in AUTH_LOG_PATHS:
        if os.path.isfile(path):
            return path
    return None


def read_log_lines(path, max_lines=5000):
    """Lê as últimas N linhas do log (evita carregar arquivos gigantes)."""
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
    """
    Procura por linhas de falha de autenticação SSH e conta quantas
    vezes cada IP apareceu. Retorna os IPs que passaram do limite
    (possível indicação de força bruta / password spraying).
    """
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


def check_listening_ports():
    """
    Lista as portas de rede atualmente em escuta usando 'ss' (ou 'netstat'
    como alternativa). Portas abertas desnecessárias são uma superfície
    de ataque que um analista deve sempre revisar.
    """
    try:
        result = subprocess.run(
            ["ss", "-tulnp"], capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip().splitlines()
    except FileNotFoundError:
        try:
            result = subprocess.run(
                ["netstat", "-tulnp"], capture_output=True, text=True, timeout=5
            )
            return result.stdout.strip().splitlines()
        except FileNotFoundError:
            return ["[!] Nem 'ss' nem 'netstat' disponíveis neste sistema."]
    except Exception as e:
        return [f"[!] Erro ao listar portas: {e}"]


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

    report["listening_ports"] = check_listening_ports()

    return report


def print_human_report(report):
    """Imprime o relatório de forma legível no terminal, com alertas destacados."""
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
        print("  Nenhum novo usuário detectado no período analisado.")

    print("\n[Uso de sudo (elevação de privilégio)]")
    if report["sudo_usage"]:
        for entry in report["sudo_usage"][-10:]:  # mostra os 10 mais recentes
            print(f"  {entry['user']} executou: {entry['command']}")
    else:
        print("  Nenhum uso de sudo registrado no período analisado.")

    print("\n[Portas em escuta (superfície de ataque)]")
    for line in report["listening_ports"]:
        print(f"  {line}")

    print("\n" + "=" * 60)
    if report["brute_force_suspects"]:
        print("[ALERTA] Há IPs com múltiplas falhas de login — investigar possível força bruta.")
    else:
        print("[OK] Nenhum indício de força bruta detectado nesta varredura.")
    print("=" * 60)


def save_json_report(report, path="security_report.json"):
    with open(path, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\n[+] Relatório salvo em {path}")


def main():
    parser = argparse.ArgumentParser(description="Linux Security Monitor - monitoramento básico de segurança.")
    parser.add_argument("--once", action="store_true", help="Executa uma única varredura e sai.")
    parser.add_argument("--watch", action="store_true", help="Executa continuamente em loop.")
    parser.add_argument("--interval", type=int, default=60, help="Intervalo em segundos entre varreduras (--watch).")
    parser.add_argument("--json", action="store_true", help="Também salva o relatório em JSON.")
    args = parser.parse_args()

    if not args.once and not args.watch:
        args.once = True  # padrão: roda uma vez se nada for especificado

    if args.watch:
        print(f"[*] Monitoramento contínuo iniciado (intervalo: {args.interval}s). Ctrl+C para parar.\n")
        try:
            while True:
                report = run_scan()
                print_human_report(report)
                if args.json:
                    save_json_report(report)
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\n[*] Monitoramento interrompido pelo usuário.")
            sys.exit(0)
    else:
        report = run_scan()
        print_human_report(report)
        if args.json:
            save_json_report(report)


if __name__ == "__main__":
    main()
