"""Reading active network connections and judging their remote ports."""

import ipaddress
from dataclasses import dataclass

import psutil

from shield.core.events import Finding, Severity

# Ports that ordinary programs use all the time (tune freely).
COMMON_PORTS = {22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 993, 995, 5228, 8080, 8443}
# Ports often used by backdoors, remote-access tools, IRC bots and Tor.
SUSPICIOUS_PORTS = {1337, 4444, 5555, 6667, 9001, 12345, 31337}


@dataclass
class Connection:
    """One outgoing connection: which program talks to which address."""

    process: str
    remote_ip: str
    remote_port: int
    pid: int | None = None


def is_external(ip_text):
    """Returns True only for public internet addresses."""
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped  # ::ffff:1.2.3.4 is really the IPv4 address 1.2.3.4
    return ip.is_global


def check_ports(conn):
    """Judges the remote port of an external connection."""
    if not is_external(conn.remote_ip):
        return []
    target = f"{conn.process} -> {conn.remote_ip}:{conn.remote_port}"
    if conn.remote_port in SUSPICIOUS_PORTS:
        return [Finding(
            "suspicious_port", Severity.MEDIUM, target,
            f"{conn.process} is connected to port {conn.remote_port} on {conn.remote_ip}. "
            "This port is often used by remote-access tools and backdoors.",
        )]
    if conn.remote_port not in COMMON_PORTS:
        return [Finding(
            "unusual_port", Severity.LOW, target,
            f"{conn.process} is connected to an uncommon port ({conn.remote_port}) on "
            f"{conn.remote_ip}. Many programs do this legitimately; look closer only if "
            "you do not recognize the program.",
        )]
    return []


def _process_name(pid, cache):
    """Returns the lowercase program name for a pid, or '?' when it cannot be read."""
    if pid is None:
        return "?"
    if pid not in cache:
        try:
            cache[pid] = psutil.Process(pid).name().lower()
        except psutil.Error:
            cache[pid] = "?"
    return cache[pid]


def read_connections():
    """Returns all established TCP connections that have a remote address."""
    names = {}
    result = []
    for sock in psutil.net_connections(kind="inet"):
        if sock.status != psutil.CONN_ESTABLISHED or not sock.raddr:
            continue
        result.append(Connection(
            process=_process_name(sock.pid, names),
            remote_ip=sock.raddr.ip,
            remote_port=sock.raddr.port,
            pid=sock.pid,
        ))
    return result