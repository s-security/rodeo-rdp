#!/usr/bin/env python3
import sys
import shutil
import subprocess
import xml.etree.ElementTree as ET
import re
from datetime import datetime

BANNER = r"""
  ____  _       _ _        _    _    ____               _                 
 |  _ \(_) __ _(_) |_ __ _| |  / \  / ___|_____      __| |__   ___  _   _ 
 | | | | |/ _` | | __/ _` | | / _ \| |   / _ \ \ /\ / /| '_ \ / _ \| | | |
 | |_| | | (_| | | || (_| | |/ ___ \ |__| (_) \ V  V / | |_) | (_) | |_| |
 |____/|_|\__, |_|\__\__,_|_/_/   \_\____\___/ \_/\_/  |_.__/ \___/ \__, |
          |___/                                                     |___/ 
"""


CVE_REGEX = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

BASE_SCRIPTS = [
    "rdp-enum-encryption",
    "rdp-ntlm-info",
    "ssl-cert",
    "ssl-enum-ciphers",
    "rdp-vuln-ms12-020",
    "rdp-vuln-cve2019-0708",
]

OPTIONAL_SCRIPTS = ["vulners"]  # not installed by default on many systems


def run_nmap(target: str, port: int, include_vulners: bool = True, host_timeout: str = "60s") -> str:
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        raise RuntimeError("nmap not found in PATH. Install Nmap first.")

    scripts = BASE_SCRIPTS + (OPTIONAL_SCRIPTS if include_vulners else [])
    script_arg = ",".join(scripts)

    cmd = [
        nmap_path,
        "-Pn",
        "-n",
        "-p",
        str(port),
        "-sV",
        "--version-light",
        "--host-timeout",
        host_timeout,
        "--script",
        script_arg,
        "-oX",
        "-",
        target,
    ]

    proc = subprocess.run(cmd, capture_output=True, text=True)

    if proc.returncode == 0 and proc.stdout.strip():
        return proc.stdout

    # If vulners isn't installed, Nmap may error. Retry without it.
    stderr = (proc.stderr or "").lower()
    if include_vulners and ("could not find script" in stderr or "failed to initialize the script engine" in stderr):
        return run_nmap(target, port, include_vulners=False, host_timeout=host_timeout)

    raise RuntimeError(f"Nmap failed.\n{proc.stderr.strip()}")


def parse_nmap_xml(xml_text: str, port: int):
    root = ET.fromstring(xml_text)

    host_el = root.find("host")
    if host_el is None:
        return None

    status_el = host_el.find("status")
    host_state = status_el.get("state") if status_el is not None else "unknown"

    addr_el = host_el.find("address")
    addr = addr_el.get("addr") if addr_el is not None else "unknown"

    port_el = None
    for p in host_el.findall("./ports/port"):
        if p.get("portid") == str(port):
            port_el = p
            break

    if port_el is None:
        return {
            "host_state": host_state,
            "address": addr,
            "port_state": "not-found",
            "service": None,
            "scripts": {},
        }

    state_el = port_el.find("state")
    port_state = state_el.get("state") if state_el is not None else "unknown"

    service_el = port_el.find("service")
    service = None
    if service_el is not None:
        service = {
            "name": service_el.get("name"),
            "product": service_el.get("product"),
            "version": service_el.get("version"),
            "extrainfo": service_el.get("extrainfo"),
            "tunnel": service_el.get("tunnel"),
        }

    scripts = {}
    for s in port_el.findall("script"):
        sid = s.get("id") or "unknown"
        out = s.get("output") or ""
        scripts[sid] = out.strip()

    return {
        "host_state": host_state,
        "address": addr,
        "port_state": port_state,
        "service": service,
        "scripts": scripts,
    }


def summarize_findings(scripts: dict):
    all_text = "\n".join(scripts.values())
    cves = sorted(set(m.group(0).upper() for m in CVE_REGEX.finditer(all_text)))

    vulns = []
    for sid, out in scripts.items():
        # Many NSE vuln scripts include "VULNERABLE" or "NOT VULNERABLE"
        upper = out.upper()
        if "VULNERABLE" in upper:
            # avoid false positives like "NOT VULNERABLE"
            if "NOT VULNERABLE" in upper or "LIKELY NOT VULNERABLE" in upper:
                continue
            vulns.append(sid)

    return cves, vulns


def print_clean(results: dict, target: str, port: int):
    print(BANNER.rstrip())
    print(f"Target: {target} ({results.get('address')})")
    print(f"Port:   {port}/tcp")
    print(f"Time:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    print(f"Host:   {results.get('host_state')}")
    print(f"Port:   {results.get('port_state')}")
    svc = results.get("service")
    if svc:
        parts = [svc.get("name"), svc.get("product"), svc.get("version"), svc.get("extrainfo")]
        parts = [p for p in parts if p]
        if parts:
            print(f"Service: {' | '.join(parts)}")
    print()

    scripts = results.get("scripts", {})
    cves, vulns = summarize_findings(scripts)

    if vulns:
        print("Vulnerability Flags:")
        for v in vulns:
            print(f"  - {v}")
        print()
    else:
        print("Vulnerability Flags: none detected by NSE checks")
        print()

    if cves:
        print("CVEs Mentioned:")
        for c in cves:
            print(f"  - {c}")
        print()
    else:
        print("CVEs Mentioned: none found in script output")
        print()

    # Show key script outputs in a sane order
    ordered = [s for s in BASE_SCRIPTS + OPTIONAL_SCRIPTS if s in scripts]
    extras = [k for k in scripts.keys() if k not in ordered]
    for sid in ordered + sorted(extras):
        out = scripts.get(sid, "").strip()
        if not out:
            continue
        print(f"[{sid}]")
        # indent output for readability
        for line in out.splitlines():
            print(f"  {line}")
        print()


def main():
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python rdp_extractor.py <ip_or_host> [port]")
        print("Example: python rdp_extractor.py 192.168.1.10 3389")
        sys.exit(1)

    target = sys.argv[1].strip()
    port = 3389
    if len(sys.argv) == 3:
        try:
            port = int(sys.argv[2])
        except ValueError:
            print("Port must be an integer.")
            sys.exit(1)

    try:
        xml_text = run_nmap(target, port, include_vulners=True, host_timeout="60s")
        results = parse_nmap_xml(xml_text, port)
        if not results:
            print("No host results returned by Nmap.")
            sys.exit(2)
        print_clean(results, target, port)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(2)


if __name__ == "__main__":
    main()
