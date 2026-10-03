"""Opt-in active scanning via nmap subprocess.

Warning: active scans connect directly to the target. Decoy scanning
(-D RND:N,ME) hides your IP among random decoys; Tor routing hides it
behind an exit node at the cost of latency and scan features.
Timeouts adapt to measured RTT so long-distance scans degrade less.
"""

import os
import re
import shutil
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

TOR_PROXY = "socks4a://127.0.0.1:9050"


def tor_available(host: str = "127.0.0.1", port: int = 9050) -> bool:
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


@dataclass
class ScanResult:
    os_guess: list = field(default_factory=list)
    ports: list = field(default_factory=list)
    raw_error: str = ""
    # Extended service data worth the active contact:
    scripts: list = field(default_factory=list)  # host-level scripts if any


_PING_AVG_LINUX = re.compile(r"(?:min/avg|max|rtt min/avg)[^=]*= [\d.]+/([\d.]+)")
_PING_AVG_WINDOWS = re.compile(r"Average\s*=\s*(\d+)ms", re.IGNORECASE)


def _measure_rtt(host: str) -> float | None:
    if sys.platform == "win32":
        cmd = ["ping", "-n", "3", "-w", "5000", host]
        pattern = _PING_AVG_WINDOWS
    else:
        cmd = ["ping", "-c", "3"]
        if sys.platform == "darwin":
            cmd += ["-t", "5"]
        else:
            cmd += ["-W", "5"]
        pattern = _PING_AVG_LINUX
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=20,
            encoding="utf-8",
            errors="replace",
        )
        output = (proc.stdout or "") + (proc.stderr or "")
        match = pattern.search(output)
        if match:
            return float(match.group(1))
        # Fallback: Windows localised ping uses translated "Average" label,
        # so look for any "<number>ms" near "Average/Mittelwert/Moyenne".
        if sys.platform == "win32":
            fallback = re.search(r"=\s*(\d+)\s*ms", output, re.IGNORECASE)
            if fallback:
                return float(fallback.group(1))
        return None
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None
    except Exception:
        return None


def adaptive_host_timeout(ip: str) -> str:
    return f"{_timeout_seconds(_measure_rtt(ip))}s"


def _timeout_seconds(rtt: float | None) -> int:
    if rtt is None:
        return 120
    if rtt < 50:
        return max(15, min(int(rtt / 10), 60))
    if rtt <= 300:
        return max(30, min(int(rtt / 10), 120))
    return max(120, min(int(rtt / 2), 300))


def _nmap_candidates() -> list[str]:
    candidates: list[str] = []
    if sys.platform == "win32":
        candidates.append("nmap.exe")
        for base in (
            os.environ.get("ProgramFiles", r"C:\Program Files"),
            os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
            os.environ.get("ProgramW6432", r"C:\Program Files"),
        ):
            if base:
                candidates.append(os.path.join(base, "Nmap", "nmap.exe"))
        # Also honour an explicit NMAP_PATH env var for non-standard installs.
        env_path = os.environ.get("NMAP_PATH") or os.environ.get("NMAP_EXE")
        if env_path:
            candidates.insert(0, env_path)
    else:
        candidates.append("nmap")
    return candidates


def nmap_path() -> str | None:
    for candidate in _nmap_candidates():
        found = shutil.which(candidate)
        if found:
            return found
        # Direct file check for absolute Windows paths that may not be on PATH.
        if os.path.isfile(candidate):
            return candidate
    return None


def available() -> bool:
    return nmap_path() is not None


def _is_root() -> bool:
    if sys.platform == "win32":
        try:
            import ctypes

            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


MAX_DECOYS = 64


def _nmap_install_hint() -> str:
    if sys.platform == "win32":
        return (
            "nmap not found. Install from https://nmap.org/download.html "
            "(installer adds C:\\Program Files (x86)\\Nmap to PATH) or "
            "set NMAP_PATH to nmap.exe location."
        )
    if sys.platform == "darwin":
        return "nmap not found. Install via: brew install nmap"
    return "nmap not found. Install via: apt install nmap  /  dnf install nmap  /  pacman -S nmap"


def _sanitize_ports_spec(spec: str | None) -> list[str]:
    """Validate and convert --ports spec to nmap args. Returns arg list or []."""
    if not spec:
        return []
    s = spec.strip()
    if not s:
        return []
    # topN shorthand
    if s.lower().startswith("top"):
        try:
            n = int(s[3:])
            if 1 <= n <= 65535:
                return ["--top-ports", str(n)]
        except ValueError:
            pass
        raise ValueError(f"invalid --ports value: {spec!r} (expected topN)")
    # Basic validation: allow digits, commas, dashes, spaces
    if not re.match(r"^[\d,\-\s]+$", s):
        raise ValueError(f"invalid --ports value: {spec!r}")
    # Normalise spaces
    s = s.replace(" ", "")
    return ["-p", s]


def scan(
    ip: str,
    log,
    decoys: int = 0,
    tor: bool = False,
    ports: str | None = None,
    udp: bool = False,
    scripts: str = "default,http-title,http-server-header,ssl-cert,ssl-enum-ciphers,banner",
    intensity: int = 5,
) -> ScanResult:
    exe = nmap_path()
    if exe is None:
        return ScanResult(raw_error=_nmap_install_hint())

    if decoys > MAX_DECOYS:
        log(f"[yellow]{decoys} decoys exceeds the sane limit — clamping to {MAX_DECOYS}[/yellow]")
        decoys = MAX_DECOYS

    # Validate/prepare port spec early so user gets fast feedback
    try:
        port_args = _sanitize_ports_spec(ports)
    except ValueError as exc:
        return ScanResult(raw_error=str(exc))

    if udp and tor:
        log("[yellow]--udp ignored with --tor (Tor is TCP-only)[/yellow]")
        udp = False

    if udp and not _is_root():
        log("[yellow]--udp requested but not root — UDP scan will be limited/unprivileged[/yellow]")

    # Clamp intensity
    intensity = max(0, min(9, int(intensity) if intensity is not None else 5))

    use_tor = False
    if tor:
        if tor_available():
            use_tor = True
            log("routing through Tor SOCKS proxy (connect scan only, OS detection disabled)")
        else:
            log("[yellow]Tor requested but nothing listening on 127.0.0.1:9050 — scanning direct[/yellow]")
    if decoys > 0:
        log(f"mixing your IP among {decoys} random decoys")

    host_timeout = "180s" if use_tor else adaptive_host_timeout(ip)
    log(f"adaptive host-timeout: {host_timeout}")
    if port_args:
        log(f"port spec: {' '.join(port_args)}")
    if scripts and scripts.strip():
        log(f"NSE scripts: {scripts.strip()}")
    log(f"version intensity: {intensity}")

    result = _run_nmap(ip, host_timeout, decoys, use_tor, log, port_args, udp, scripts, intensity)

    # Thin results on long-distance targets usually mean the timeout fired
    # early — retry once at double the budget (skipped over Tor: too slow).
    if not use_tor and not result.raw_error and len(result.ports) <= 1:
        escalated = f"{min(int(host_timeout[:-1]) * 2, 480)}s"
        if escalated != host_timeout:
            log(f"[yellow]thin result ({len(result.ports)} ports) — retrying with host-timeout {escalated}[/yellow]")
            retry = _run_nmap(ip, escalated, decoys, use_tor, log, port_args, udp, scripts, intensity)
            if len(retry.ports) > len(result.ports):
                log(f"[green]escalated scan found {len(retry.ports)} ports[/green]")
                result = retry
    return result


def _run_nmap(
    ip: str,
    host_timeout: str,
    decoys: int,
    use_tor: bool,
    log,
    port_args: list[str] | None = None,
    udp: bool = False,
    scripts: str = "",
    intensity: int = 5,
) -> ScanResult:
    stealth_opts: list[str] = []
    # Version detection: intensity 0-9; default 5 balances accuracy vs time
    scan_type = ["-sV", "--version-intensity", str(intensity)]
    if use_tor:
        scan_type = ["-sT", "--proxies", TOR_PROXY]
    if decoys > 0:
        stealth_opts += ["-D", f"RND:{decoys},ME"]
    if _is_root() and not use_tor:
        stealth_opts += ["-O", "--osscan-guess"]
    elif not use_tor:
        log("OS fingerprint via nmap skipped (needs root/admin); falling back to passive sources")

    # Port selection
    port_opts: list[str] = list(port_args or [])
    # UDP adds a second scan type; nmap supports combined -sS -sU style but we keep TCP primary
    scan_types: list[str] = list(scan_type)
    if udp:
        # Use SYN+UDP when root, otherwise connect+UDP fallback
        if _is_root() and not use_tor:
            scan_types = ["-sS", "-sU", "--version-intensity", str(intensity)]
        else:
            scan_types = ["-sT", "-sU", "--version-intensity", str(intensity)]
        if not port_args:
            # Default UDP top ports when not specifying custom ports
            port_opts = ["--top-ports", "100"]

    script_opts: list[str] = []
    if scripts and scripts.strip() and not use_tor:
        # NSE scripts are noisy + Tor-unfriendly; skip over Tor
        cleaned = scripts.strip().strip(",")
        if cleaned:
            # Validate script names to prevent argument injection (only alnum, dash, underscore, dot, comma)
            if not re.match(r"^[a-zA-Z0-9_\-,\.\s]+$", cleaned):
                log(f"[yellow]Invalid --scripts value rejected (allowed: a-z, 0-9, _ - . ,): {cleaned}[/yellow]")
            elif re.search(r"(^|,)\s*-", cleaned):
                log(f"[yellow]Invalid --scripts value rejected (scripts must not look like flags): {cleaned}[/yellow]")
            else:
                script_opts = ["--script", cleaned]

    exe = nmap_path() or "nmap"
    cmd = [
        exe,
        "-Pn",
        *scan_types,
        *stealth_opts,
        *port_opts,
        *script_opts,
        "-T4",
        "--max-retries",
        "3",
        "--host-timeout",
        host_timeout,
        "-oX",
        "-",
        ip,
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=900,
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.TimeoutExpired:
        return ScanResult(raw_error="nmap timed out after 15 minutes")
    except FileNotFoundError:
        return ScanResult(raw_error=_nmap_install_hint())
    except OSError as exc:
        return ScanResult(raw_error=f"failed to launch nmap: {exc}")

    result = ScanResult()
    if proc.returncode != 0:
        result.raw_error = proc.stderr.strip() or f"nmap exited {proc.returncode}"
        return result

    try:
        root = ET.fromstring(proc.stdout)
    except ET.ParseError:
        return ScanResult(raw_error="could not parse nmap XML output")

    for osmatch in root.iter("osmatch"):
        result.os_guess.append(f"{osmatch.get('name', '?')} ({osmatch.get('accuracy', '?')}%)")

    # Host-level scripts (e.g., from --script at host level)
    for hostscript in root.iter("hostscript"):
        for script in hostscript.iter("script"):
            sid = script.get("id", "")
            out = script.get("output", "")[:300]
            if sid:
                result.scripts.append({"id": sid, "output": out})

    for port_el in root.iter("port"):
        state_el = port_el.find("state")
        service_el = port_el.find("service")
        if state_el is None or state_el.get("state") != "open":
            continue
        # Extended service info
        cpes: list[str] = []
        extrainfo = hostname = ostype = devicetype = method = conf = ""
        if service_el is not None:
            for cpe_el in service_el.findall("cpe"):
                if cpe_el.text:
                    cpes.append(cpe_el.text)
            cpe = cpes[0] if cpes else ""
            extrainfo = service_el.get("extrainfo", "")
            hostname = service_el.get("hostname", "")
            ostype = service_el.get("ostype", "")
            devicetype = service_el.get("devicetype", "")
            method = service_el.get("method", "")
            conf = service_el.get("conf", "")
        else:
            cpe = ""
        # Per-port scripts
        port_scripts: dict[str, str] = {}
        for script in port_el.findall("script"):
            sid = script.get("id", "")
            out = script.get("output", "")[:500]
            if sid:
                port_scripts[sid] = out
        result.ports.append(
            {
                "port": port_el.get("portid", "?"),
                "protocol": port_el.get("protocol", "tcp"),
                "service": (service_el.get("name", "") if service_el is not None else ""),
                "product": (service_el.get("product", "") if service_el is not None else ""),
                "version": (service_el.get("version", "") if service_el is not None else ""),
                "extrainfo": extrainfo,
                "hostname": hostname,
                "ostype": ostype,
                "devicetype": devicetype,
                "method": method,
                "conf": conf,
                "cpe": cpe,
                "cpes": cpes,
                "scripts": port_scripts,
                "state_reason": state_el.get("reason", ""),
            }
        )
    return result
