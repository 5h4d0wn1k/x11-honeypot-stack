#!/usr/bin/env python3
"""Tests for X11 - Honeypot Stack."""
import asyncio
import json
import os
import socket
import subprocess
import sys
import threading
import time
import unittest

FIRMWARE = os.path.join(os.path.dirname(__file__), os.pardir, "firmware")
ROOT = os.path.join(os.path.dirname(__file__), os.pardir)
if FIRMWARE not in sys.path:
    sys.path.insert(0, FIRMWARE)

from honeypot_stack import (
    SSHHoneypot, TelnetHoneypot, CowrieAnalytics, EMBEDDED_EVENTS,
    HTTPAdminHandler, FAKE_ADMIN_PAGE,
)


class TestCowrieAnalytics(unittest.TestCase):
    def setUp(self):
        self.analytics = CowrieAnalytics(EMBEDDED_EVENTS)

    def test_report_keys(self):
        report = self.analytics.generate_report()
        expected = {"total_events", "total_login_attempts", "successful_logins",
                    "failed_logins", "total_commands", "unique_src_ips",
                    "top_src_ips", "top_usernames", "top_passwords",
                    "protocols", "top_commands", "timeline", "sessions"}
        self.assertTrue(expected.issubset(set(report.keys())))

    def test_event_counts(self):
        report = self.analytics.generate_report()
        self.assertGreater(report["total_events"], 0)
        self.assertGreater(report["total_login_attempts"], 0)

    def test_top_src_ips(self):
        report = self.analytics.generate_report()
        self.assertGreater(len(report["top_src_ips"]), 0)
        top_ip = report["top_src_ips"][0][0]
        self.assertEqual(top_ip, "185.220.101.42")

    def test_protocols(self):
        report = self.analytics.generate_report()
        self.assertIn("ssh", report["protocols"])
        self.assertIn("telnet", report["protocols"])

    def test_print_report(self):
        report = self.analytics.generate_report()
        self.analytics.print_report(report)


class TestSSHHoneypot(unittest.TestCase):
    def test_banner_constant(self):
        self.assertIn("SSH-2.0", SSHHoneypot.BANNER)

    def test_events_list_init(self):
        hp = SSHHoneypot(host="127.0.0.1", port=22290)
        self.assertEqual(hp.events, [])


class TestTelnetHoneypot(unittest.TestCase):
    def test_banner(self):
        hp = TelnetHoneypot(host="127.0.0.1", port=22291)
        self.assertIn(b"Ubuntu", hp.BANNER)

    def test_events_list_init(self):
        hp = TelnetHoneypot(host="127.0.0.1", port=22291)
        self.assertEqual(hp.events, [])


class TestHTTPAdminHandler(unittest.TestCase):
    def test_admin_page(self):
        self.assertIn("Admin Login", FAKE_ADMIN_PAGE)
        self.assertIn("Router Admin Panel", FAKE_ADMIN_PAGE)


class TestLiveSSH(unittest.TestCase):
    def test_ssh_connect_and_login(self):
        hp = SSHHoneypot(host="127.0.0.1", port=22295)
        loop = asyncio.new_event_loop()

        def _serve():
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(hp.run(duration=2.5))
            except Exception:
                pass

        t = threading.Thread(target=_serve, daemon=True)
        t.start()
        time.sleep(0.4)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect(("127.0.0.1", 22295))
            banner = s.recv(1024)
            self.assertIn(b"SSH-2.0", banner)
            s.sendall(b"root\n")
            time.sleep(0.2)
            s.sendall(b"test\n")
            time.sleep(0.2)
            s.close()
        except Exception:
            pass
        t.join(timeout=3.0)
        self.assertGreater(len(hp.events), 0)


class TestLiveTelnet(unittest.TestCase):
    def test_telnet_connect(self):
        hp = TelnetHoneypot(host="127.0.0.1", port=22296)
        t = threading.Thread(target=lambda: hp.run(duration=2.0), daemon=True)
        t.start()
        time.sleep(0.3)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect(("127.0.0.1", 22296))
            banner = s.recv(1024)
            self.assertIn(b"Ubuntu", banner)
            s.sendall(b"admin\n")
            time.sleep(0.2)
            s.sendall(b"pass\n")
            time.sleep(0.3)
            s.close()
        except Exception:
            pass
        time.sleep(1.5)
        self.assertGreater(len(hp.events), 0)


class TestDemo(unittest.TestCase):
    def test_demo_exit_zero(self):
        r = subprocess.run(
            [sys.executable, os.path.join(FIRMWARE, "honeypot_stack.py")],
            capture_output=True, text=True, cwd=ROOT, timeout=30)
        self.assertEqual(r.returncode, 0)
        self.assertIn("Self-test PASSED", r.stdout)


class TestCLI(unittest.TestCase):
    def test_help(self):
        r = subprocess.run(
            [sys.executable, os.path.join(FIRMWARE, "honeypot_stack.py"), "--help"],
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn("Honeypot", r.stdout)

    def test_dry_run(self):
        r = subprocess.run(
            [sys.executable, os.path.join(FIRMWARE, "honeypot_stack.py"), "--dry-run"],
            capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(r.returncode, 0)


class TestPyCompile(unittest.TestCase):
    def test_compile(self):
        r = subprocess.run(
            [sys.executable, "-m", "py_compile",
             os.path.join(FIRMWARE, "honeypot_stack.py")],
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
