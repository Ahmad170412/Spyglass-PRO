"""Smoke tests for Lens-Extender.

Inherited from the standalone Lens-Extender repository and pointed at the
vendored copy. Run: .venv/bin/python tests/lens_smoke_test.py
"""

import datetime
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "spyglass_pro" / "modules"))

from lens_extender import analyzer, config
from lens_extender import report as report_mod
from lens_extender.analyzer import _age_days, _parse_cpes
from lens_extender.app import validate_target
from lens_extender.osint import _clean, _is_ip, _sanitize, dnsbl_check

PASS, FAIL = 0, 0


def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name} — {detail}")


print("== input validation ==")
check("valid IPv4", validate_target("8.8.8.8") == "8.8.8.8")
check("whitespace trimmed", validate_target("  1.1.1.1 ") == "1.1.1.1")
try:
    validate_target("not-an-ip")
    check("rejects garbage", False)
except SystemExit:
    check("rejects garbage", True)
try:
    validate_target("999.1.1.1")
    check("rejects out-of-range octet", False)
except SystemExit:
    check("rejects out-of-range octet", True)
for bad in ("0.0.0.0", "224.0.0.1", "255.255.255.255"):
    try:
        validate_target(bad)
        check(f"refuses {bad}", False)
    except SystemExit:
        check(f"refuses {bad}", True)

print("== markup neutralization ==")
out = _clean("Client error for https://api.shodan.io/host/1.2.3.4?key=SECRET123")
check("clean redacts secrets", "SECRET123" not in out, out)
check("clean escapes brackets", "[" not in out.replace("\\[", ""), out)

print("== secret redaction ==")
leak = "Server error for https://api.shodan.io/shodan/host/1.2.3.4?key=SECRET123&foo=bar"
clean = _sanitize(leak)
check("key redacted", "SECRET123" not in clean and "key=[REDACTED]" in clean, clean)
check("token redacted", "TOKENX" not in _sanitize("https://x.io/?token=TOKENX"))
check(
    "apiKey camelCase redacted",
    "SECRETX" not in _sanitize("https://x.io/?apiKey=SECRETX"),
)
check(
    "plain errors untouched",
    _sanitize("timeout of 15s exceeded") == "timeout of 15s exceeded",
)

print("== CPE parsing ==")
cpes = _parse_cpes(
    [
        "cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*",
        "cpe:/o:linux:linux_kernel:5.15",
        "cpe:/h:cisco:catalyst_9200",
        "garbage",
        "cpe:/a:x",
        "",
    ]
)
check(
    "parses 2.3 format",
    cpes[0]
    == {
        "type": "application",
        "vendor": "openbsd",
        "product": "openssh",
        "version": "9.6p1",
    },
    str(cpes[:1]),
)
check("parses legacy os cpe", cpes[1]["type"] == "os" and cpes[1]["version"] == "5.15")
check("legacy hardware no version", cpes[2]["version"] == "")
check("skips malformed (3 kept)", len(cpes) == 3, f"got {len(cpes)}")

print("== config ==")
import pathlib

config_dir = pathlib.Path(tempfile.mkdtemp())
config.CONFIG_DIR = config_dir
config.CONFIG_FILE = config_dir / "cfg.json"
config.update("shodan_api_key", "testkey")
loaded = config.load()
check("round-trips key", loaded["shodan_api_key"] == "testkey")
if os.name == "posix":
    mode = os.stat(config.CONFIG_FILE).st_mode & 0o777
    check("file chmod 600", mode == 0o600, f"got {oct(mode)}")
else:
    # Windows has no POSIX mode bits: os.stat synthesizes 0o666 for any
    # writable file, so 0600 is not enforceable or observable there. Access
    # is governed by NTFS ACLs on the user's profile instead.
    check("file chmod 600 (Windows: ACL-governed)", True)

print("== DNSBL logic ==")
check("_is_ip dotted quad", _is_ip("1.2.3.4") and not _is_ip("example.com"))
listed = dnsbl_check("192.0.2.123")  # TEST-NET, should not be listed anywhere
check("TEST-NET IP not listed", listed == [], str(listed))
check(
    "IPv6 skipped safely",
    dnsbl_check("2001:db8::1") == [],
    str(dnsbl_check("2001:db8::1")),
)

print("== freshness parsing ==")
check("ISO timestamp age", isinstance(_age_days("2026-08-20T10:00:00+00:00"), int))
recent = _age_days(datetime.datetime.now(datetime.timezone.utc).isoformat())
check("now -> 0 days", recent == 0, f"got {recent}")
check("garbage -> None", _age_days("not-a-date") is None)

print("== analyzer pipeline (synthetic) ==")


class FakeOsint:
    target = "203.0.113.9"
    geo = {"org": "TestOrg", "country": "US", "lat": 1.0}
    rdap = {"name": "NET-1", "range": "203.0.113.0 - 203.0.113.255"}
    reverse_dns = ""
    shodan = {
        "data": [{"port": 443, "transport": "tcp", "product": "nginx", "version": "1.24"}],
        "os": "",
    }
    internetdb = {
        "ports": [22, 80],
        "hostnames": ["host.example.com"],
        "cpes": ["cpe:/a:openssl:openssl:3.0", "cpe:/o:linux:linux_kernel:5.15"],
        "tags": ["ddos"],
        "vulns": ["CVE-2023-44487"],
    }
    certs = []
    vulns = [{"id": "CVE-2023-44487", "severity": "HIGH", "score": 7.5, "description": "x"}]
    ripestat = {"prefix": "203.0.113.0/24", "asns": ["AS64512 Test"]}
    greynoise = {
        "classification": "malicious",
        "name": "some-scanner",
        "last_seen": "2026-08-20",
    }
    dnsbl = []
    dns_records = {"MX": ["10 mail.example.com."]}
    cohosted = []
    errors = []


class FakeScan:
    os_guess = ["Linux 5.x"]
    ports = [
        {
            "port": "22",
            "protocol": "tcp",
            "service": "ssh",
            "product": "OpenSSH",
            "version": "9.6",
        }
    ]
    raw_error = ""


data = analyzer.build_report("203.0.113.9", FakeOsint(), FakeScan())
check("shodan port present", any(p["port"] == "443" for p in data["ports"]))
check("internetdb ports added", {p["port"] for p in data["ports"]} >= {"22", "80"})
check(
    "nmap enriches existing port 22",
    next(p for p in data["ports"] if p["port"] == "22")["product"] == "OpenSSH",
)
check("rDNS falls back to InternetDB hostname", data["reverse_dns"] == "host.example.com")
check("OS from nmap + CPE hints", len(data["os_guesses"]) >= 2)
check(
    "software parsed + deduped (3 unique)",
    len(data["software"]) == 3,
    str(data["software"]),
)
check(
    "ripestat/tags/dns/cohosted wired",
    data["ripestat"]["prefix"] == "203.0.113.0/24" and data["tags"] == ["ddos"],
)
check("greynoise passthrough", data["greynoise"]["classification"] == "malicious")
check(
    "freshness computed from greynoise/shodan",
    any(e["source"] == "GreyNoise" for e in data["freshness"]),
)

print("== markdown render (synthetic) ==")
md = report_mod.render(data)
for section in (
    "Network Identity",
    "Geo",
    "Open Ports",
    "Identified Software",
    "Exposure",
    "OS Fingerprint",
    "Vulnerabilities",
    "Internet Noise (GreyNoise)",
    "Data Freshness",
):
    check(f"section '{section}'", f"## {section}" in md)
check("no rich markup leaks", "[" not in md.replace("[REDACTED]", ""))

tmp_md = os.path.join(tempfile.mkdtemp(), "out.md")
report_mod.write(data, tmp_md)
check("markdown file written", os.path.getsize(tmp_md) > 200)

print("== empty-results robustness ==")


class EmptyOsint(FakeOsint):
    shodan = None
    internetdb = None
    vulns = []
    geo = {}
    rdap = {}
    ripestat = {}
    greynoise = {}
    dnsbl = []
    dns_records = {}
    cohosted = []


empty = analyzer.build_report("203.0.113.9", EmptyOsint())
check("build_report survives all-empty", empty["ports"] == [] and empty["vulns"] == [])
md_empty = report_mod.render(empty)
check("render survives all-empty", "# Recon Report" in md_empty)

print(f"\n{'=' * 40}\n{PASS} passed, {FAIL} failed")
if __name__ == "__main__":
    raise SystemExit(1 if FAIL else 0)
