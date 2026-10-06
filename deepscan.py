#!/usr/bin/env python3
"""Deep scan modules for cyber-audit.

Each module wraps a proven open-source tool and maps its output to the common
finding schema. Imported by audit.py via the MODULE registry, so adding a new
tool is a new function + one registry line — no changes elsewhere.

All modules are read-only except when allow_intrusive is set, which switches
nuclei/nmap to active templates/scripts. Requires authorization (gated upstream).
"""

from __future__ import annotations

import json
import re
import socket
import subprocess
import urllib.error
import urllib.request

try:
    from audit import finding, scan_error
except ImportError:  # running as a package
    from .audit import finding, scan_error


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _run(cmd, timeout):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _primary_web_port(cfg):
    """First http/https port to use for web tools."""
    ports = list(cfg.get("http_ports") or []) + list(cfg.get("tls_ports") or [])
    return ports[0] if ports else 80


def _web_url(target, cfg, port=None):
    port = port or _primary_web_port(cfg)
    scheme = "https" if port in (cfg.get("tls_ports") or []) else "http"
    default = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    return f"{scheme}://{target}" + ("" if default else f":{port}")


# --------------------------------------------------------------------------
# Web vulnerability scanners
# --------------------------------------------------------------------------

# Nuclei templates that touch nothing destructive — always safe to run.
NUCLEI_SAFE_TAGS = ["cve", "misconfig", "exposure", "default-login", "tech", "takeover"]
# Templates that can knock a service over or hammer it — never run by default.
NUCLEI_NEVER_TAGS = ["dos", "fuzz"]
NUCLEI_ACTIVE_TAGS = ["intrusive", "brute-force"]


def scan_nuclei(target, cfg):
    """nuclei — fast, template-driven CVE/misconfig/exposure engine.

    Uses nuclei's real feature set so one tool covers thousands of checks:
      - severity filter      (-severity)
      - tag include/exclude   (-tags / -exclude-tags) — safe-by-default tag sets
      - custom templates      (-t templates/files)
      - rate + concurrency    (-rate-limit / -concurrency) — gentle on customer infra
      - retries + timeout     (-retries / -timeout)
      - request headers       (-header)
      - privacy               (-no-interactsh) — no out-of-band callbacks by default
      - template auto-update  (-update-templates)
      - JSONL output with full evidence (CVE/CWE/CVSS + extracted results)

    Configure via the "nuclei" block in the scan config. Active/intrusive tags
    require cfg["allow_intrusive"] (set by --intrusive).
    """
    opts = cfg.get("nuclei") or {}
    intrusive = bool(cfg.get("allow_intrusive"))

    cmd = [
        "nuclei", "-u", _web_url(target, cfg), "-jsonl", "-silent", "-no-color",
        "-timeout", str(opts.get("timeout", 10)),
        "-retries", str(opts.get("retries", 1)),
        "-rate-limit", str(opts.get("rate_limit", 150)),
        "-concurrency", str(opts.get("concurrency", 25)),
        "-severity", ",".join(opts.get("severity")
                              or ["info", "low", "medium", "high", "critical"]),
    ]

    # Tag selection: explicit config wins, else safe defaults unless intrusive.
    tags = opts.get("tags")
    if not tags and not intrusive:
        tags = NUCLEI_SAFE_TAGS
    if tags:
        cmd += ["-tags", ",".join(tags)]

    # DoS/fuzz are never run; active tags only with explicit opt-in.
    exclude = set(opts.get("exclude_tags") or []) | set(NUCLEI_NEVER_TAGS)
    if not intrusive:
        exclude |= set(NUCLEI_ACTIVE_TAGS)
    cmd += ["-exclude-tags", ",".join(sorted(exclude))]

    for t in opts.get("templates") or []:      # custom template dirs/files
        cmd += ["-t", t]
    for h in opts.get("headers") or []:        # extra request headers
        cmd += ["-header", h]

    if not opts.get("allow_oob", False):       # no interactsh callbacks
        cmd.append("-no-interactsh")
    if opts.get("update_templates"):
        cmd.append("-update-templates")
    cmd += list(opts.get("extra_args") or [])  # escape hatch for new flags

    try:
        out = _run(cmd, cfg["timeout_seconds"] * opts.get("budget", 8))
    except Exception as exc:  # noqa: BLE001
        return [scan_error("nuclei", exc)]

    findings = []
    for line in (out.stdout or "").splitlines():
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = r.get("info", {})
        cls = info.get("classification") or {}
        tid = str(r.get("template-id", "unknown"))

        # Rich evidence: location, extracted data, and any CVE/CWE/CVSS refs.
        parts = [str(r.get("matched-at") or r.get("host") or "")]
        if r.get("extracted-results"):
            parts.append("extracted: " + ", ".join(map(str, r["extracted-results"])))
        for key, label in (("cve-id", "CVE"), ("cwe-id", "CWE")):
            if cls.get(key):
                vals = cls[key] if isinstance(cls[key], list) else [cls[key]]
                parts.append(f"{label}: " + ",".join(map(str, vals)))
        if cls.get("cvss-score"):
            parts.append(f"CVSS: {cls['cvss-score']}")

        findings.append(finding(
            f"NUCLEI-{tid}",
            info.get("name") or tid,
            info.get("severity", "info"),
            " | ".join(p for p in parts if p)[:400],
            (info.get("description") or "Review the matched template and remediate.")[:400],
        ))
    return findings


def scan_nikto(target, cfg):
    """nikto — web server misconfigurations and known files."""
    port = _primary_web_port(cfg)
    ssl_flag = ["-ssl"] if port in (cfg.get("tls_ports") or []) else []
    cmd = ["nikto", "-host", target, "-port", str(port), "-Format", "json",
           "-output", "-", "-ask", "no"] + ssl_flag
    try:
        out = _run(cmd, cfg["timeout_seconds"] * 6)
    except Exception as exc:  # noqa: BLE001
        return [scan_error("nikto", exc)]

    text = out.stdout or ""
    start = text.find("{")
    if start < 0:
        return []
    try:
        data = json.loads(text[start:])
    except json.JSONDecodeError:
        return []

    findings = []
    for i, v in enumerate(data.get("vulnerabilities", []) or []):
        findings.append(finding(
            f"NIKTO-{i}",
            v.get("msg", "nikto finding"),
            "medium",
            f"{v.get('url', '')} {v.get('method', '')}".strip(),
            "Review the nikto report and harden the web server / remove exposed files.",
        ))
    return findings


def scan_whatweb(target, cfg):
    """whatweb — web technology fingerprinting (informational)."""
    cmd = ["whatweb", "--log-json=-", "--quiet", _web_url(target, cfg)]
    try:
        out = _run(cmd, cfg["timeout_seconds"])
    except Exception as exc:  # noqa: BLE001
        return [scan_error("whatweb", exc)]

    findings = []
    for line in out.stdout.splitlines():
        line = line.strip().rstrip(",")
        if not line.startswith("{"):
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        for plugin, v in (r.get("plugins") or {}).items():
            ver = ""
            if isinstance(v, dict):
                ver = " ".join(v.get("version") or [])
            findings.append(finding(
                f"WEBTECH-{plugin}",
                f"Web technology detected: {plugin}",
                "info",
                f"{plugin} {ver}".strip(),
                "Informational — use to track patching of the identified stack.",
            ))
    return findings


def scan_nmap_vuln(target, cfg, nmap_xml):
    """nmap NSE vuln scripts — known CVEs for exposed services (safe categories)."""
    scripts = "vuln" if cfg.get("allow_intrusive") else "vuln and safe"
    cmd = ["nmap", "-Pn", "-sV", "--open", "-p", cfg["ports"],
           "--script", scripts, "-oX", "-", target]
    try:
        out = _run(cmd, cfg["timeout_seconds"] * 12)
    except Exception as exc:  # noqa: BLE001
        return [scan_error("nmap-vuln", exc)]

    import xml.etree.ElementTree as ET
    findings = []
    try:
        root = ET.fromstring(out.stdout)
    except ET.ParseError:
        return findings
    for script in root.iter("script"):
        sid = script.get("id", "")
        if not sid.startswith("vuln"):
            continue
        if script.get("output", "").lower().startswith("no"):  # "no results"
            continue
        for table in script.iter("table"):
            findings.append(finding(
                f"NMAP-{sid.upper()}",
                f"nmap vuln script reported a finding: {sid}",
                "high",
                (table.get("key", "") + " " + " ".join(
                    e.text or "" for e in table.iter("elem")))
                .strip()[:300] or sid,
                "Review the NSE script output and patch the affected service.",
            ))
    return findings


def scan_testssl(target, cfg):
    """testssl.sh — full TLS/cipher/cert audit (deep replacement for basic TLS)."""
    findings = []
    for port in cfg.get("tls_ports") or [443]:
        cmd = ["testssl.sh", "--quiet", "--jsonfile-pretty", "-", f"{target}:{port}"]
        try:
            out = _run(cmd, cfg["timeout_seconds"] * 6)
        except Exception as exc:  # noqa: BLE001
            findings.append(scan_error("testssl", exc))
            continue
        text = out.stdout or ""
        start = text.find("{")
        if start < 0:
            continue
        try:
            data = json.loads(text[start:])
        except json.JSONDecodeError:
            continue
        for sc in data.get("scanResult", []) or []:
            if sc.get("severity") in ("HIGH", "CRITICAL", "MEDIUM", "WARN"):
                sev = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
                       "WARN": "medium"}.get(sc["severity"], "low")
                findings.append(finding(
                    f"TLS-{port}-{sc.get('id', 'X')}",
                    sc.get("finding", sc.get("id", "TLS issue")),
                    sev,
                    f"port {port}: {sc.get('finding', '')}",
                    "Review the testssl.sh finding and reconfigure TLS accordingly.",
                ))
    return findings


# --------------------------------------------------------------------------
# Recon
# --------------------------------------------------------------------------

def scan_dns(target, cfg):
    """DNS/email hardening: SPF, DMARC, zone transfer."""
    findings = []
    domain = cfg.get("domain") or target
    if re.fullmatch(r"[\d.]+", domain):
        return findings  # bare IP — no DNS/email checks

    for name, rec in (("SPF", "TXT"), ("DMARC", "TXT")):
        q = f"v=spf1" if name == "SPF" else f"_dmarc.{domain}"
        host = domain if name == "SPF" else q
        try:
            out = _run(["dig", "+short", "TXT", host], cfg["timeout_seconds"])
        except Exception as exc:  # noqa: BLE001
            findings.append(scan_error("dns", exc))
            continue
        txt = out.stdout or ""
        if name == "SPF" and "v=spf1" not in txt:
            findings.append(finding(
                "DNS-SPF", "No SPF record — email spoofing possible", "medium",
                f"dig TXT {domain} returned no v=spf1",
                "Publish an SPF TXT record for the domain.",
            ))
        if name == "DMARC" and "v=DMARC1" not in txt:
            findings.append(finding(
                "DNS-DMARC", "No DMARC record — email spoofing possible", "medium",
                f"dig TXT _dmarc.{domain} returned no v=DMARC1",
                "Publish a DMARC record with a policy (p=quarantine/reject).",
            ))

    try:
        out = _run(["dig", "+short", "AXFR", domain], cfg["timeout_seconds"])
        if out.stdout and "Transfer failed" not in out.stdout and len(out.stdout) > 20:
            findings.append(finding(
                "DNS-AXFR", "DNS zone transfer (AXFR) is allowed", "high",
                out.stdout[:200],
                "Restrict AXFR to authorized secondary nameservers.",
            ))
    except Exception:  # noqa: BLE001
        pass
    return findings


def scan_services(target, cfg):
    """Exposed database services reachable and possibly unauthenticated."""
    risky = {3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis"}
    findings = []
    for port, name in risky.items():
        try:
            with socket.create_connection((target, port), timeout=cfg["timeout_seconds"]):
                pass
        except OSError:
            continue
        findings.append(finding(
            f"EXPOSED-{name.upper()}",
            f"{name} port {port} is exposed to the network",
            "high",
            f"TCP {port} open ({name})",
            f"Bind {name} to localhost or restrict access; never expose it publicly.",
        ))
    return findings


def scan_container_api(target, cfg):
    """Docker / Kubernetes API exposure."""
    findings = []
    endpoints = [
        (2375, "http", "Docker API (unencrypted)"),
        (2376, "https", "Docker API (TLS)"),
        (6443, "https", "Kubernetes API"),
        (10250, "https", "Kubelet API"),
    ]
    for port, scheme, label in endpoints:
        url = f"{scheme}://{target}:{port}/version"
        try:
            ctx = None
            if scheme == "https":
                import ssl
                ctx = ssl._create_unverified_context()
            req = urllib.request.Request(url, headers={"User-Agent": "cyber-audit"})
            with urllib.request.urlopen(req, timeout=cfg["timeout_seconds"], context=ctx) as resp:
                body = resp.read(200).decode("utf-8", "ignore")
        except Exception:  # noqa: BLE001
            continue
        findings.append(finding(
            f"CONTAINER-{port}",
            f"{label} exposed on port {port}",
            "critical" if port == 2375 else "high",
            body.strip()[:200],
            "Never expose the container/orchestrator API publicly; require auth + TLS.",
        ))
    return findings


# --------------------------------------------------------------------------
# Cloud configuration audit (ScoutSuite) — different category: uses read-only
# cloud API credentials, not network scanning.
# --------------------------------------------------------------------------

# ScoutSuite's numeric rule levels -> our severity names.
_SCOUT_LEVELS = {1: "info", 2: "low", 3: "medium", 4: "high", 5: "critical"}


def scan_cloud(target, cfg):
    """ScoutSuite — multi-cloud (AWS/Azure/GCP) configuration audit.

    Needs read-only API credentials (mounted read-only), not a host target.
    Enabled only when cfg["cloud"] specifies a provider. Findings are read from
    the ScoutSuite JSON report and mapped to the common schema.
    """
    cloud = cfg.get("cloud") or {}
    provider = cloud.get("provider")
    if not provider:
        return []  # nothing to do — cloud audit not requested

    import glob
    report_dir = cloud.get("report_dir") or "/app/out/scoutsuite"
    cmd = ["python3", "-m", "ScoutSuite", "scan", provider,
           "--report-dir", report_dir, "--no-browser"]

    # ScoutSuite accepts profiles, regions, and per-service selection.
    if cloud.get("profile"):
        cmd += ["--profile", cloud["profile"]]
    if cloud.get("regions"):
        cmd += ["--regions", ",".join(cloud["regions"])]
    if cloud.get("services"):
        cmd += ["--services", ",".join(cloud["services"])]
    if cloud.get("cli") is False:      # use boto/sdk creds instead of CLI
        cmd.append("--no-cli")

    try:
        out = _run(cmd, cfg["timeout_seconds"] * cloud.get("budget", 30))
        if not glob.glob(report_dir.rstrip("/") + "/*.json"):
            raise RuntimeError(out.stderr.strip() or "ScoutSuite produced no report")
    except Exception as exc:  # noqa: BLE001
        return [scan_error("cloud", exc)]

    # Newest report wins.
    reports = sorted(glob.glob(report_dir.rstrip("/") + "/*.json"),
                     key=lambda p: __import__("os").path.getmtime(p))
    with open(reports[-1], encoding="utf-8") as fh:
        data = json.load(fh)

    findings = []
    for section in ("metadata",):
        data.pop(section, None)
    for svc_name, svc in data.items():
        if not isinstance(svc, dict):
            continue
        for fid, f in (svc.get("findings") or {}).items():
            if not f.get("flagged"):
                continue
            sev = _SCOUT_LEVELS.get(f.get("level"), "medium")
            findings.append(finding(
                f"SCOUT-{fid}",
                f"{svc_name}: {f.get('description', fid)}",
                sev,
                f.get("rationale", "")[:300] or fid,
                f.get("remediation", "Review the ScoutSuite finding and remediate.")
                or "Review the ScoutSuite finding and remediate.",
            ))
    return findings


# --------------------------------------------------------------------------
# Registry — audit.py iterates this for deep mode.
# --------------------------------------------------------------------------

DEEP_MODULES = {
    "nuclei": scan_nuclei,
    "nikto": scan_nikto,
    "whatweb": scan_whatweb,
    "nmap_vuln": scan_nmap_vuln,
    "testssl": scan_testssl,
    "dns": scan_dns,
    "services": scan_services,
    "container": scan_container_api,
    "cloud": scan_cloud,
}
