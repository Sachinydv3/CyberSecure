"""TCP-connect port scanner.

For each port in ``COMMON_PORTS`` we attempt a ``connect()`` with a small
per-port timeout. A successful connect → port is open; refusal or timeout
→ port is closed/filtered (we don't distinguish — that's a job for SYN
scan, which requires raw sockets and root).

Concurrency is bounded by a thread pool so a 25-port probe completes in
``~timeout/parallelism`` seconds rather than the serial worst case.
"""

from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Iterable, List, Optional


# Curated subset of well-known ports. Anything not listed is simply not
# probed. Each entry has a (label, default_severity_if_open) pair.
COMMON_PORTS: Dict[int, Dict[str, str]] = {
    21:    {"service": "FTP",        "severity": "medium"},
    22:    {"service": "SSH",        "severity": "medium"},
    23:    {"service": "Telnet",     "severity": "high"},
    25:    {"service": "SMTP",       "severity": "medium"},
    53:    {"service": "DNS",        "severity": "low"},
    80:    {"service": "HTTP",       "severity": "info"},
    110:   {"service": "POP3",       "severity": "medium"},
    139:   {"service": "NetBIOS",    "severity": "high"},
    143:   {"service": "IMAP",       "severity": "medium"},
    443:   {"service": "HTTPS",      "severity": "info"},
    445:   {"service": "SMB",        "severity": "high"},
    587:   {"service": "SMTP-TLS",   "severity": "medium"},
    993:   {"service": "IMAPS",      "severity": "low"},
    995:   {"service": "POP3S",      "severity": "low"},
    1433:  {"service": "MSSQL",      "severity": "high"},
    1521:  {"service": "Oracle DB",  "severity": "high"},
    2049:  {"service": "NFS",        "severity": "high"},
    3306:  {"service": "MySQL",      "severity": "high"},
    3389:  {"service": "RDP",        "severity": "high"},
    5432:  {"service": "PostgreSQL", "severity": "high"},
    5900:  {"service": "VNC",        "severity": "high"},
    6379:  {"service": "Redis",      "severity": "high"},
    8000:  {"service": "HTTP-alt",   "severity": "info"},
    8080:  {"service": "HTTP-proxy", "severity": "info"},
    8443:  {"service": "HTTPS-alt",  "severity": "info"},
    9200:  {"service": "Elasticsearch", "severity": "high"},
    27017: {"service": "MongoDB",    "severity": "high"},
}


# Ports that should never be reachable from the public internet — if they
# are, that's a high-severity finding regardless of the table above.
HIGH_RISK_DB_PORTS = {1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 9200, 27017}


def _is_loopback(host: str) -> bool:
    """Return True if ``host`` resolves to a loopback / private / link-local address.

    Conservative: anything we can't classify is treated as *not* loopback
    so the caller's localhost-only gate keeps working as expected.
    """
    if host.lower() in {"localhost", "ip6-localhost", "ip6-loopback"}:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # Probably a hostname. Try to resolve to a single address.
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror:
            return False
        if not infos:
            return False
        try:
            ip = ipaddress.ip_address(infos[0][4][0])
        except (ValueError, IndexError):
            return False
    return (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
    )


def _probe(host: str, port: int, timeout: float) -> bool:
    """Return True if a TCP connect to ``(host, port)`` succeeds within ``timeout``."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def scan_ports(
    host: str,
    ports: Optional[Iterable[int]] = None,
    timeout: float = 1.0,
    max_workers: int = 16,
) -> List[Dict]:
    """Probe ``host`` on each port in ``ports`` (defaults to ``COMMON_PORTS``).

    Returns a list of finding dicts, one per *open* port. Closed / filtered
    ports produce no finding.
    """
    if not host:
        return []

    port_list = sorted(ports if ports is not None else COMMON_PORTS.keys())
    # Cap workers so we don't spawn hundreds of threads for a tiny port list.
    workers = max(1, min(max_workers, len(port_list)))
    open_findings: List[Dict] = []

    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_to_port = {
            pool.submit(_probe, host, p, timeout): p for p in port_list
        }
        for fut in as_completed(future_to_port):
            port = future_to_port[fut]
            try:
                is_open = fut.result()
            except Exception:
                is_open = False
            if not is_open:
                continue
            meta = COMMON_PORTS.get(port, {"service": "unknown", "severity": "info"})
            # DB/admin ports are always escalated to high when open.
            severity = "high" if port in HIGH_RISK_DB_PORTS else meta["severity"]
            open_findings.append({
                "severity": severity,
                "category": "open-port",
                "title": f"Open port: {port}/{meta['service']}",
                "detail": (
                    f"TCP connect to {host}:{port} succeeded. The service "
                    f"'{meta['service']}' is reachable from this scanner."
                ),
                "recommendation": (
                    "If this service is not intentionally exposed, block the "
                    "port at the firewall or disable the service. For admin "
                    "panels and database listeners, restrict access to trusted "
                    "source IPs only."
                ),
                "port": port,
                "service": meta["service"],
            })

    open_findings.sort(key=lambda f: f["port"])
    return open_findings
