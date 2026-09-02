"""Tests for scanner.port_checks — TCP-connect scanner.

We spin up a real socket bound to 127.0.0.1 on a random port and
confirm the scanner detects it as open. We do not mock — the whole
point of this test is to exercise the actual probe path.
"""

import socket
import threading
from contextlib import contextmanager

from django.test import SimpleTestCase

from scanner import port_checks


@contextmanager
def _listening_server():
    """Yield (host, port) of a bound, listening socket on 127.0.0.1."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(5)
    try:
        host, port = sock.getsockname()
        yield host, port
    finally:
        sock.close()


def _accept_in_background(sock):
    """Accept connections in a daemon thread until told to stop."""
    stop = threading.Event()

    def loop():
        sock.settimeout(0.2)
        while not stop.is_set():
            try:
                client, _ = sock.accept()
                client.close()
            except socket.timeout:
                continue
            except OSError:
                break

    t = threading.Thread(target=loop, daemon=True)
    t.start()

    def shutdown():
        stop.set()
        t.join(timeout=2)

    return shutdown


class PortScannerTests(SimpleTestCase):
    def test_detects_open_loopback_port(self):
        with _listening_server() as (host, port):
            findings = port_checks.scan_ports(
                host,
                ports=[port],
                timeout=1.0,
                max_workers=2,
            )
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["port"], port)
        self.assertEqual(f["category"], "open-port")

    def test_closed_port_produces_no_finding(self):
        # Bind + immediately close to claim a port that's almost
        # certainly closed. The scanner should report nothing.
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        _, closed_port = sock.getsockname()
        sock.close()

        findings = port_checks.scan_ports(
            "127.0.0.1",
            ports=[closed_port],
            timeout=0.5,
            max_workers=2,
        )
        self.assertEqual(findings, [])

    def test_db_port_is_high_severity(self):
        # 5432 (PostgreSQL) is in HIGH_RISK_DB_PORTS regardless of the
        # service table's default.
        with _listening_server() as (host, port):
            # Patch the port list to include our random port and treat
            # it like a high-risk DB port.
            original_high = set(port_checks.HIGH_RISK_DB_PORTS)
            port_checks.HIGH_RISK_DB_PORTS = original_high | {port}
            try:
                findings = port_checks.scan_ports(
                    host,
                    ports=[port],
                    timeout=1.0,
                    max_workers=2,
                )
            finally:
                port_checks.HIGH_RISK_DB_PORTS = original_high

        self.assertEqual(findings[0]["severity"], "high")

    def test_is_loopback_helper(self):
        self.assertTrue(port_checks._is_loopback("127.0.0.1"))
        self.assertTrue(port_checks._is_loopback("localhost"))
        self.assertTrue(port_checks._is_loopback("10.0.0.1"))
        self.assertTrue(port_checks._is_loopback("192.168.1.1"))
        self.assertFalse(port_checks._is_loopback("8.8.8.8"))
        self.assertFalse(port_checks._is_loopback("example.com"))
