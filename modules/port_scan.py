import socket
import asyncio
from concurrent.futures import ThreadPoolExecutor
from modules.resolver import resolve_domain

TOP_PORTS = [
    (21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"),
    (53, "DNS"), (80, "HTTP"), (110, "POP3"), (143, "IMAP"),
    (443, "HTTPS"), (445, "SMB"), (993, "IMAPS"), (995, "POP3S"),
    (1433, "MSSQL"), (3306, "MySQL"), (3389, "RDP"), (5432, "PostgreSQL"),
    (5900, "VNC"), (6379, "Redis"), (8080, "HTTP-Alt"), (8443, "HTTPS-Alt"),
]


def _check_port(ip: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


async def run_portscan(domain: str, timeout: float = 2.0) -> dict:
    try:
        ip = resolve_domain(domain)
    except Exception as e:
        return {"domain": domain, "found": False, "error": f"Could not resolve: {e}"}

    loop = asyncio.get_event_loop()
    results = []

    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = []
        for port, service in TOP_PORTS:
            fut = loop.run_in_executor(pool, _check_port, ip, port, timeout)
            futures.append((port, service, fut))

        for port, service, fut in futures:
            is_open = await fut
            results.append({
                "port": port,
                "service": service,
                "open": is_open,
            })

    open_ports = [r for r in results if r["open"]]
    return {
        "domain": domain,
        "ip": ip,
        "total_open": len(open_ports),
        "total_scanned": len(TOP_PORTS),
        "results": results,
    }
