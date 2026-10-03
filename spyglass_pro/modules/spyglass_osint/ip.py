"""IP address reconnaissance — PASSIVE ONLY.

Resolves the address and reads third-party sources: WHOIS registries,
Shodan, reverse DNS. It does not port scan. The nmap scan this module used
to run on every call was removed rather than switched off, so nothing here
opens a connection to the host.
"""

import re
import socket

from .utils import _SHODAN, _WHOIS, _check_tool, _curl_json, _run


def address(target):
    target = target.strip()
    ip = _resolve(target)
    if not ip:
        return {"error": f"Could not resolve: {target}"}

    r = {"ip": ip}

    geo = _ip_api(ip)
    if geo:
        r["geo"] = geo

    rdns = _reverse_dns(ip)
    if rdns:
        r["hostname"] = rdns

    hostname = target if _is_domain(target) else rdns
    if hostname:
        a_recs = _dns_a(hostname)
        if a_recs:
            r["a_records"] = a_recs

    who = _whois_lookup(ip)
    if who:
        r["whois"] = who

    if _SHODAN:
        sd = _shodan_lookup(ip)
        if sd:
            r["shodan"] = sd

    return r


def _is_domain(s):
    return not s.replace(".", "").isdigit() and ":" not in s


def _resolve(target):
    if _is_domain(target):
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            return None
    try:
        socket.inet_aton(target)
        return target
    except socket.error:
        return None


def _reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return None


def _dns_a(hostname):
    if not hostname:
        return None
    addrs = []
    try:
        for res in socket.getaddrinfo(hostname, 0, socket.AF_INET):
            addr = res[4][0]
            if addr not in addrs:
                addrs.append(addr)
    except socket.gaierror:
        pass
    return addrs if addrs else None


def _ip_api(ip):
    url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,lat,lon,timezone,query"
    data = _curl_json(url)
    if data and data.get("status") == "success":
        return {
            "country": data.get("country"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "as": data.get("as"),
            "location": f"{data['lat']},{data['lon']}",
            "timezone": data.get("timezone"),
        }
    return None


def _whois_lookup(ip):
    if not _check_tool("whois", _WHOIS):
        return None
    out = _run(["whois", "-h", "whois.arin.net", ip], timeout=15)
    if not out or "error" in out.lower()[:50]:
        return None
    result = {}
    for field in ("NetName", "Organization", "Country", "CIDR", "NetRange"):
        m = re.search(rf"^{field}:\s*(.+)$", out, re.MULTILINE)
        if m:
            result[field.lower()] = m.group(1).strip()
    return result if result else None


def _shodan_lookup(ip):
    out = _run(["shodan", "host", ip], timeout=30)
    if not out or "error" in out.lower()[:50]:
        return None
    lines = out.splitlines()
    ports = []
    hostnames = set()
    for line in lines:
        m = re.match(r"^(\d+)/", line)
        if m:
            ports.append(int(m.group(1)))
        if "hostnames:" in line.lower():
            parts = line.split(":", 1)[1].strip().strip("[]")
            if parts:
                for h in parts.replace(";", ",").split(","):
                    h = h.strip().strip("'\"")
                    if h:
                        hostnames.add(h)
    sd = {}
    if ports:
        sd["ports"] = sorted(ports)[:50]
    if hostnames:
        sd["hostnames"] = sorted(hostnames)[:10]
    return sd if sd else None

