#!/usr/bin/env python3
"""Cyber Audit — external security benchmark scanner.

Point it at an authorized host; it probes open ports, service versions, SSH
hardening, TLS/certificate health and HTTP security headers, then writes a
summary HTML report plus machine-readable findings.

Read-only: no exploitation, no writes, no DoS payloads.
See docs/TEST-PLAN.md for scope and rules of engagement.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from html.parser import HTMLParser

VERSION = "1.0.0"

SEVERITY_WEIGHT = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 0}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
RISK_FULL_SCORE = 40  # weight units that equal a score of 100


# --------------------------------------------------------------------------
# Finding helpers
# --------------------------------------------------------------------------

def finding(fid, title, severity, evidence, remediation):
    """Build one finding in the common schema. Never raises on bad severity."""
    sev = severity if severity in SEVERITY_WEIGHT else "info"
    return {
        "id": fid,
        "title": title,
        "severity": sev,
        "evidence": str(evidence),
        "remediation": remediation,
    }


def scan_error(module, exc):
    return finding(
        "SCAN-ERROR",
        f"Module '{module}' could not complete",
        "info",
        f"{type(exc).__name__}: {exc}",
        "Check tool availability, target reachability and scan window.",
    )


# --------------------------------------------------------------------------
# Modules
# --------------------------------------------------------------------------

def scan_ports(target, cfg):
    """T6: TCP port sweep + service/version banners via nmap XML output (with socket fallback)."""
    try:
        out = subprocess.run(
            ["nmap", "-Pn", "-sV", "--open", "-p", cfg["ports"], "-oX", "-", target],
            capture_output=True, text=True, timeout=cfg["timeout_seconds"] * 10,
        )
        if out.returncode != 0:
            raise RuntimeError(out.stderr.strip() or f"nmap exited {out.returncode}")

        findings = []
        root = ET.fromstring(out.stdout)
        for port in root.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = port.get("portid")
            service = port.find("service") or ET.Element("service")
            svc_name = service.get("name", "unknown")
            product = " ".join(
                p for p in [service.get("product", ""), service.get("version", "")] if p
            ).strip()
            banner = f"{portid}/{port.get('protocol')} {svc_name} {product}".strip()

            pnum = int(portid)
            sev = "medium" if pnum not in (80, 443) else "low"
            findings.append(finding(
                f"PORT-{portid}",
                f"Port {portid} ({svc_name}) is exposed",
                sev,
                banner,
                "Close the port or restrict it to trusted source addresses.",
            ))
            if product:
                findings.append(finding(
                    f"SVC-BANNER-{portid}",
                    f"Service on port {portid} advertises a version banner",
                    "low",
                    banner,
                    "Suppress version banners to slow down attacker reconnaissance.",
                ))
        return findings, out.stdout
    except (FileNotFoundError, OSError):
        # Native socket port sweep fallback
        findings = []
        ports = []
        for part in str(cfg.get("ports", "80,443,22")).split(","):
            part = part.strip()
            if "-" in part:
                try:
                    s, e = part.split("-", 1)
                    ports.extend(range(int(s), min(int(e) + 1, int(s) + 50)))
                except ValueError:
                    pass
            elif part.isdigit():
                ports.append(int(part))
        for pnum in ports[:150]:
            try:
                with socket.create_connection((target, pnum), timeout=0.6) as s:
                    banner = f"{pnum}/tcp open"
                    try:
                        s.settimeout(0.5)
                        b = s.recv(1024).decode("utf-8", errors="ignore").strip()
                        if b:
                            banner = f"{pnum}/tcp {b[:60]}"
                    except Exception:
                        pass
                    sev = "medium" if pnum not in (80, 443) else "low"
                    findings.append(finding(
                        f"PORT-{pnum}",
                        f"Port {pnum} is open",
                        sev,
                        banner,
                        "Close the port or restrict it to trusted source addresses.",
                    ))
            except Exception:
                pass
        return findings, None


def scan_outdated(nmap_xml, cfg, policy):
    """T7: compare detected versions against the minimum-safe policy."""
    findings = []
    if not nmap_xml:
        return findings
    try:
        root = ET.fromstring(nmap_xml)
    except ET.ParseError:
        return findings

    for service in root.iter("service"):
        product = (service.get("product") or "").lower()
        version = service.get("version") or ""
        if not product or not version:
            continue
        for name, rule in policy.items():
            if name.startswith("_"):
                continue
            if name.lower() in product and _version_lt(version, rule["min"]):
                findings.append(finding(
                    f"SVC-OUTDATED-{name}",
                    f"Outdated {name} detected ({version})",
                    rule.get("severity", "high"),
                    f"banner reports {product} {version}; minimum safe is {rule['min']}",
                    rule.get("remediation", f"Upgrade {name} to {rule['min']} or newer."),
                ))
    return findings


def _parse_version(v):
    nums = re.findall(r"\d+", v)
    return tuple(int(n) for n in nums[:3]) or (0,)


def _version_lt(found, minimum):
    a, b = _parse_version(found), _parse_version(minimum)
    n = max(len(a), len(b))
    a = a + (0,) * (n - len(a))
    b = b + (0,) * (n - len(b))
    return a < b


def scan_ssh(target, cfg):
    """T8: SSH hardening via ssh-audit JSON output (with banner grab fallback)."""
    p = cfg["ssh_port"]
    try:
        out = subprocess.run(
            ["ssh-audit", "-j", f"{target}:{p}"],
            capture_output=True, text=True, timeout=cfg["timeout_seconds"],
        )
        if not (out.stdout or "").strip():
            raise RuntimeError(out.stderr.strip() or "ssh-audit returned no output")
        data = json.loads(out.stdout)

        findings = []
        for section in ("kex", "key", "enc", "mac"):
            for entry in data.get(section, []) or []:
                alg = entry.get("algorithm", "?")
                for note in entry.get("notes", []) or []:
                    if note.get("level") in ("fail", "warn"):
                        sev = "high" if note["level"] == "fail" else "medium"
                        findings.append(finding(
                            f"SSH-{section.upper()}-{alg}",
                            f"SSH {section} weakness: {alg}",
                            sev,
                            note.get("text", ""),
                            "Remove legacy/deprecated algorithms in sshd_config "
                            f"({section.upper()}Algorithms).",
                        ))
        # Banner/protocol hints.
        banner = data.get("banner") or {}
        sw = banner.get("software") or ""
        if sw:
            findings.append(finding(
                "SSH-BANNER", "SSH server discloses software version", "low",
                f"banner: {sw}",
                "Set a generic SSH banner / suppress version disclosure.",
            ))
        if not findings:
            findings.append(finding(
                "SSH-OK", "SSH configuration passed the hardening check", "info",
                "no failing or warned algorithms reported",
                "No action required.",
            ))
        return findings
    except (FileNotFoundError, OSError):
        # Native socket banner grab fallback
        findings = []
        try:
            with socket.create_connection((target, p), timeout=min(cfg.get("timeout_seconds", 5), 3)) as sock:
                sock.settimeout(2.0)
                banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                if banner:
                    findings.append(finding(
                        "SSH-BANNER", "SSH server discloses software banner", "low",
                        f"banner: {banner}",
                        "Suppress or generalize SSH version banner in sshd_config.",
                    ))
        except Exception:
            pass
        return findings


def scan_tls(target, cfg):
    """T9: certificate validity and supported protocol version (stdlib ssl)."""
    findings = []
    for port in cfg.get("tls_ports", [443]):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((target, port), timeout=cfg["timeout_seconds"]) as sock:
                with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                    proto = ssock.version()
                    cert = ssock.getpeercert()
        except Exception as exc:  # noqa: BLE001 - port may simply be closed
            findings.append(finding(
                f"TLS-{port}-UNREACHABLE",
                f"TLS endpoint {port} not reachable",
                "info",
                f"{type(exc).__name__}: {exc}",
                "Confirm whether a TLS service is expected on this port.",
            ))
            continue

        if proto in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            findings.append(finding(
                f"TLS-{port}-PROTO", f"Legacy TLS protocol supported on {port}",
                "high", f"negotiated {proto}",
                "Disable TLS < 1.2; allow only TLS 1.2/1.3.",
            ))

        if not cert:  # verification was off; inspect the DER blob instead
            findings.append(finding(
                f"TLS-{port}-UNVERIFIED", f"Certificate on {port} could not be verified",
                "medium", "peer certificate failed validation",
                "Install a certificate from a trusted CA and check the chain.",
            ))
            continue

        exp = cert.get("notAfter")
        if exp:
            try:
                exp_dt = dt.datetime.strptime(exp, "%b %d %H:%M:%S %Y %Z")
                days = (exp_dt - dt.datetime.utcnow()).days
                if days < 0:
                    findings.append(finding(
                        f"TLS-{port}-EXPIRED", f"Certificate on {port} has expired",
                        "critical", f"expired {exp}",
                        "Renew the certificate immediately.",
                    ))
                elif days < 21:
                    findings.append(finding(
                        f"TLS-{port}-EXPIRING", f"Certificate on {port} expires in {days} days",
                        "medium", f"notAfter {exp}",
                        "Renew the certificate before expiry.",
                    ))
            except ValueError:
                pass
    return findings


SECURITY_HEADERS = {
    "Strict-Transport-Security": ("medium", "Add HSTS on HTTPS responses."),
    "X-Content-Type-Options": ("low", "Set X-Content-Type-Options: nosniff."),
    "X-Frame-Options": ("medium", "Set X-Frame-Options / CSP frame-ancestors."),
    "Content-Security-Policy": ("medium", "Define a Content-Security-Policy."),
    "Referrer-Policy": ("low", "Set a Referrer-Policy."),
}


def scan_http(target, cfg):
    """T10: missing security headers and server banner leakage (stdlib urllib)."""
    findings = []
    for port in cfg.get("http_ports", [80]):
        scheme = "https" if port in cfg.get("tls_ports", [443]) else "http"
        url = f"{scheme}://{target}:{port}/"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "cyber-audit"})
            ctx = ssl._create_unverified_context() if scheme == "https" else None
            with urllib.request.urlopen(req, timeout=cfg["timeout_seconds"], context=ctx) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
        except urllib.error.HTTPError as e:
            headers = {k.lower(): v for k, v in (e.headers or {}).items()}
        except Exception as exc:  # noqa: BLE001 - port may be closed
            findings.append(finding(
                f"HTTP-{port}-UNREACHABLE", f"HTTP endpoint {port} not reachable",
                "info", f"{type(exc).__name__}: {exc}",
                "Confirm whether an HTTP service is expected on this port.",
            ))
            continue

        for header, (sev, rem) in SECURITY_HEADERS.items():
            if header.lower() not in headers:
                findings.append(finding(
                    f"HTTP-{port}-HDR-{header}", f"Missing header on {port}: {header}",
                    sev, f"{header} absent in response", rem,
                ))
        server = headers.get("server", "")
        if server and re.search(r"\d", server):
            findings.append(finding(
                f"HTTP-{port}-SERVER", f"Server banner on {port} exposes a version",
                "low", f"Server: {server}",
                "Hide the Server header / remove version numbers.",
            ))
    return findings


# --------------------------------------------------------------------------
# HTTPS, API & On-Page Security Testing
# --------------------------------------------------------------------------

class _PageSecurityParser(HTMLParser):
    def __init__(self, base_url=""):
        super().__init__()
        self.base_url = base_url
        self.is_https = base_url.lower().startswith("https://")
        self.in_form = False
        self.current_form_action = ""
        self.current_form_method = "get"
        self.current_form_has_csrf = False
        self.current_form_has_password = False
        self.forms = []
        self.mixed_content = []

    def handle_starttag(self, tag, attrs):
        attr_dict = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self.in_form = True
            self.current_form_action = attr_dict.get("action", "")
            self.current_form_method = attr_dict.get("method", "get").lower()
            self.current_form_has_csrf = False
            self.current_form_has_password = False
        elif self.in_form and tag == "input":
            itype = attr_dict.get("type", "text").lower()
            iname = (attr_dict.get("name", "") + " " + attr_dict.get("id", "")).lower()
            if any(term in iname for term in ("csrf", "token", "authenticity_token", "_token", "xsrf")):
                self.current_form_has_csrf = True
            if itype == "password":
                self.current_form_has_password = True
        elif tag in ("script", "link", "iframe", "img"):
            src = attr_dict.get("src") or attr_dict.get("href") or ""
            if self.is_https and src.lower().startswith("http://"):
                self.mixed_content.append((tag, src))

    def handle_endtag(self, tag):
        if tag == "form" and self.in_form:
            self.forms.append({
                "action": self.current_form_action,
                "method": self.current_form_method,
                "has_csrf": self.current_form_has_csrf,
                "has_password": self.current_form_has_password,
            })
            self.in_form = False


def analyze_html_security(html_content, url=""):
    """Evaluates HTML source for forms without CSRF, mixed content, and leaked secrets."""
    findings = []
    parser = _PageSecurityParser(url)
    try:
        parser.feed(html_content)
    except Exception:
        pass

    # 1. Forms inspection
    for idx, form in enumerate(parser.forms, start=1):
        action = form["action"]
        method = form["method"]
        has_csrf = form["has_csrf"]
        has_password = form["has_password"]
        is_plain_target = action.lower().startswith("http://") or (not parser.is_https and not action.lower().startswith("https://"))
        if has_password and is_plain_target:
            findings.append(finding(
                f"ONPAGE-INSECURE-FORM-{idx}",
                "Password form submits credentials over insecure plaintext HTTP",
                "high",
                f"Form action '{action or 'current URL'}' transmits password over plaintext HTTP",
                "Submit all authentication and sensitive forms over HTTPS.",
            ))
        if method == "post" and not has_csrf:
            findings.append(finding(
                f"ONPAGE-NO-CSRF-{idx}",
                "Form missing Anti-CSRF token protection",
                "medium",
                f"POST form action '{action}' contains no anti-CSRF token field",
                "Add a unique, unpredictable anti-CSRF token to state-changing forms.",
            ))

    # 2. Mixed content
    if parser.mixed_content:
        for tag, src in parser.mixed_content:
            findings.append(finding(
                f"ONPAGE-MIXED-CONTENT-{tag}",
                f"Mixed Content: HTTPS page loads {tag} over insecure HTTP",
                "medium",
                f"<{tag}> source: {src}",
                "Ensure all sub-resources (scripts, stylesheets, frames) use HTTPS.",
            ))

    # 3. Client-side secret & credential leakage
    secret_patterns = [
        (r"\b(sk_live_[0-9a-zA-Z]{20,})\b", "Live Stripe secret key"),
        (r"\b(pk_live_[0-9a-zA-Z]{20,})\b", "Live Stripe publishable key"),
        (r"\b(AKIA[0-9A-Z]{16})\b", "AWS Access Key ID"),
        (r"\b(ghp_[0-9a-zA-Z]{30,})\b", "GitHub Personal Access Token"),
        (r"(aws_secret_access_key\s*=\s*['\"][^'\"]+['\"])", "AWS Secret Access Key"),
        (r"<!--\s*(?:TODO|FIXME|NOTE):?.*?(?:secret|password|api[_-]?key|token|credential).*?-->", "Sensitive developer comment"),
    ]
    for pat, label in secret_patterns:
        matches = re.findall(pat, html_content, flags=re.IGNORECASE)
        for m in matches:
            findings.append(finding(
                f"ONPAGE-SECRET-LEAK-{label.replace(' ', '-').upper()}",
                f"Exposed client-side secret/sensitive data: {label}",
                "high" if ("secret" in label.lower() or "access key" in label.lower()) else "medium",
                f"Matched pattern for {label}: {m[:60]}",
                "Remove credentials and sensitive development comments from client-facing assets.",
            ))

    return findings


def scan_onpage(target, cfg):
    """Audits client-side HTML on target website for security flaws and secret leaks."""
    findings = []
    port = (cfg.get("tls_ports") or [443])[0]
    scheme = "https" if port in (cfg.get("tls_ports") or []) else "http"
    url = f"{scheme}://{target}:{port}/"
    try:
        ctx = ssl._create_unverified_context() if scheme == "https" else None
        req = urllib.request.Request(url, headers={"User-Agent": "cyber-audit/1.0"})
        with urllib.request.urlopen(req, timeout=cfg.get("timeout_seconds", 60), context=ctx) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            findings.extend(analyze_html_security(body, url))
    except Exception as exc:
        findings.append(finding(
            "ONPAGE-UNREACHABLE",
            f"Could not retrieve web page on {url} for on-page audit",
            "info",
            f"{type(exc).__name__}: {exc}",
            "Verify web endpoint is active and accessible.",
        ))
    return findings


def evaluate_api_response(endpoint, status, headers, body=""):
    """Inspects API endpoint status, headers and payload for security disclosures."""
    findings = []
    # 1. Exposed API documentation / schema
    if status == 200:
        norm_body = body.lower()
        if any(term in endpoint.lower() for term in ("swagger", "openapi", "api-docs", "graphql", "actuator")):
            if any(kw in norm_body for kw in ("swagger", "openapi", "paths", "info", "graphql", "graphiql", "actuator", "beans", "health")):
                findings.append(finding(
                    f"API-DOCS-EXPOSED-{endpoint}",
                    f"Exposed API schema/docs endpoint: {endpoint}",
                    "medium",
                    f"Status 200 on {endpoint} with schema disclosures",
                    "Restrict API docs and metadata endpoints from public internet access.",
                ))

    # 2. CORS checks
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "").lower()
    if acao == "*":
        if acac == "true":
            findings.append(finding(
                "API-CORS-WILDCARD-CREDENTIALS",
                "CORS misconfiguration: wildcard origin allowed with credentials",
                "critical",
                "Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true",
                "Specify explicit trusted origins when credentials are supported.",
            ))
        else:
            findings.append(finding(
                "API-CORS-WILDCARD",
                "API CORS allows wildcard origin (*)",
                "low",
                "Access-Control-Allow-Origin: *",
                "Ensure public CORS is intended for this API endpoint.",
            ))

    # 3. Stack trace / debug error leaks
    if status >= 500 or "traceback (most recent call last)" in body.lower() or ("stacktrace" in body.lower() and "exception" in body.lower()):
        findings.append(finding(
            "API-STACKTRACE-LEAK",
            "API endpoint exposes internal stack trace / unhandled error",
            "high",
            f"Verbose exception or stack trace returned on {endpoint}",
            "Disable debug mode and implement generic error responses.",
        ))

    return findings


API_PROBE_ENDPOINTS = [
    "/openapi.json", "/swagger.json", "/swagger-ui.html", "/api/docs",
    "/v1/api-docs", "/v2/api-docs", "/graphql", "/actuator", "/actuator/env",
    "/metrics", "/api/health"
]


def scan_api(target, cfg):
    """Probes REST & GraphQL API endpoints for schema exposure, CORS and dangerous methods."""
    findings = []
    port = (cfg.get("tls_ports") or [443])[0]
    scheme = "https" if port in (cfg.get("tls_ports") or []) else "http"
    base_url = f"{scheme}://{target}:{port}"
    ctx = ssl._create_unverified_context() if scheme == "https" else None
    timeout = min(cfg.get("timeout_seconds", 60), 10)

    # 1. Probe common endpoints & CORS
    for ep in API_PROBE_ENDPOINTS:
        url = f"{base_url}{ep}"
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "cyber-audit/1.0",
                    "Origin": "https://evil-attacker.example",
                }
            )
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
                body = resp.read(65536).decode("utf-8", errors="ignore")
                findings.extend(evaluate_api_response(ep, resp.status, hdrs, body))
        except urllib.error.HTTPError as e:
            hdrs = {k.lower(): v for k, v in (e.headers or {}).items()}
            try:
                body = e.read(16384).decode("utf-8", errors="ignore")
            except Exception:
                body = ""
            findings.extend(evaluate_api_response(ep, e.code, hdrs, body))
        except Exception:
            pass

    # 2. Probe dangerous methods
    try:
        req = urllib.request.Request(f"{base_url}/", method="OPTIONS", headers={"User-Agent": "cyber-audit/1.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            allow = resp.headers.get("Allow", "").upper()
            for d_m in ("TRACE", "PUT", "DELETE"):
                if d_m in allow:
                    findings.append(finding(
                        f"API-METHOD-{d_m}",
                        f"Insecure HTTP method {d_m} advertised on API root",
                        "medium" if d_m != "TRACE" else "high",
                        f"Allow header contains: {allow}",
                        f"Disable {d_m} method on the web server if not strictly required.",
                    ))
    except Exception:
        pass

    return findings


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def evaluate_https_security(http_status=None, http_location=None, https_headers=None):
    """Validates HTTP-to-HTTPS redirect, HSTS enforcement, and Secure/HttpOnly cookies."""
    findings = []
    # 1. HTTP -> HTTPS redirect
    if http_status is not None:
        if http_status not in (301, 302, 307, 308) or not (http_location and http_location.lower().startswith("https://")):
            findings.append(finding(
                "HTTPS-NO-REDIRECT",
                "Plain HTTP requests are not redirected to HTTPS",
                "medium",
                f"HTTP status: {http_status}, Location: {http_location or 'none'}",
                "Configure web server to redirect all HTTP traffic to HTTPS (301 Moved Permanently).",
            ))

    # 2. HTTPS headers and cookies
    if https_headers:
        # HSTS
        if "strict-transport-security" not in https_headers:
            findings.append(finding(
                "HTTPS-MISSING-HSTS",
                "Strict-Transport-Security (HSTS) header missing on HTTPS",
                "medium",
                "Strict-Transport-Security header is not present",
                "Enable HSTS with max-age=31536000 and includeSubDomains.",
            ))
        # Cookies
        cookie_hdr = https_headers.get("set-cookie", "")
        if cookie_hdr:
            raw_cookies = [c.strip() for c in cookie_hdr.split("\n") if c.strip()] or [cookie_hdr]
            for c in raw_cookies:
                c_lower = c.lower()
                c_name = c.split("=")[0].strip() if "=" in c else "cookie"
                if "secure" not in c_lower:
                    findings.append(finding(
                        f"HTTPS-COOKIE-INSECURE-{c_name}",
                        f"Cookie '{c_name}' missing Secure flag",
                        "medium",
                        f"Set-Cookie: {c[:80]}",
                        "Add the 'Secure' attribute so the cookie is only sent over HTTPS.",
                    ))
                if "httponly" not in c_lower:
                    findings.append(finding(
                        f"HTTPS-COOKIE-NO-HTTPONLY-{c_name}",
                        f"Cookie '{c_name}' missing HttpOnly flag",
                        "low",
                        f"Set-Cookie: {c[:80]}",
                        "Add the 'HttpOnly' attribute to protect against XSS credential theft.",
                    ))
                if "samesite" not in c_lower:
                    findings.append(finding(
                        f"HTTPS-COOKIE-NO-SAMESITE-{c_name}",
                        f"Cookie '{c_name}' missing SameSite attribute",
                        "low",
                        f"Set-Cookie: {c[:80]}",
                        "Set SameSite=Lax or SameSite=Strict to defend against CSRF attacks.",
                    ))
    return findings


def scan_https(target, cfg):
    """Verifies HTTPS redirect enforcement and checks cookie security attributes."""
    findings = []
    timeout = min(cfg.get("timeout_seconds", 60), 10)

    # 1. Test HTTP port redirection
    http_port = (cfg.get("http_ports") or [80])[0]
    opener = urllib.request.build_opener(_NoRedirectHandler)
    http_status, http_loc = None, None
    try:
        resp = opener.open(f"http://{target}:{http_port}/", timeout=timeout)
        http_status = resp.status
        http_loc = resp.headers.get("Location")
    except urllib.error.HTTPError as e:
        http_status = e.code
        http_loc = e.headers.get("Location")
    except Exception:
        pass

    # 2. Test HTTPS port headers and cookies
    https_port = (cfg.get("tls_ports") or [443])[0]
    https_headers = None
    try:
        ctx = ssl._create_unverified_context()
        req = urllib.request.Request(f"https://{target}:{https_port}/", headers={"User-Agent": "cyber-audit/1.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            https_headers = {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as e:
        https_headers = {k.lower(): v for k, v in (e.headers or {}).items()}
    except Exception:
        pass

    findings.extend(evaluate_https_security(http_status, http_loc, https_headers))
    return findings


# --------------------------------------------------------------------------
# Normalize / score / report
# --------------------------------------------------------------------------

def normalize(all_findings):
    """T11: validate schema, dedupe by (id, evidence), order by severity."""
    seen, out = set(), []
    for f in all_findings:
        if not isinstance(f, dict):
            continue
        if not all(k in f for k in ("id", "title", "severity", "evidence", "remediation")):
            continue
        key = (f["id"], f["evidence"])
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    out.sort(key=lambda f: SEVERITY_ORDER.index(f["severity"]))
    return out


def score(findings):
    """T11: severity counts, weighted risk score (0-100) and band."""
    counts = {s: 0 for s in SEVERITY_ORDER}
    total = 0
    for f in findings:
        counts[f["severity"]] += 1
        total += SEVERITY_WEIGHT[f["severity"]]
    value = min(100, round(total * 100 / RISK_FULL_SCORE))
    band = "Low" if value < 25 else "Moderate" if value < 50 else "High" if value < 75 else "Critical"
    return {"score": value, "band": band, "counts": counts}


CYBER_BANNER = r"""
  ___ _   _ ___  ___ ___      _   _   _ ___ ___ _____ 
 / __| | | | _ )| __| _ \    /_\ | | | |   \_ _|_   _|
| (__| |_| | _ \| _||   /   / _ \| |_| | |) | |  | |  
 \___|\__, |___/|___|_|_\  /_/ \_\\___/|___/___| |_|  
      |___/                                           
 [>> CYBERSECURITY ENGINEER AUTOMATED DEFENSE & AUDIT SUITE <<]
"""


def render_html(target, meta, findings, summary, coverage=None):
    """T12: summary report — score, counts, one line per finding."""
    cov = ", ".join(coverage) if coverage else "core"
    esc = lambda s: (str(s).replace("&", "&").replace("<", "<").replace(">", ">"))
    colors = {
        "critical": "#ff0055",
        "high": "#ff5e00",
        "medium": "#eab308",
        "low": "#06b6d4",
        "info": "#64748b",
    }
    glows = {
        "critical": "rgba(255, 0, 85, 0.4)",
        "high": "rgba(255, 94, 0, 0.4)",
        "medium": "rgba(234, 179, 8, 0.4)",
        "low": "rgba(6, 182, 212, 0.4)",
        "info": "rgba(100, 116, 139, 0.4)",
    }

    rows = "\n".join(
        f'<tr class="finding-row" data-sev="{f["severity"]}">'
        f'<td><span class="sev" style="background:{colors[f["severity"]]};box-shadow:0 0 12px {glows[f["severity"]]}">'
        f'{f["severity"].upper()}</span></td>'
        f'<td><b class="title-text">{esc(f["title"])}</b>'
        f'<div class="ev-code"><code>{esc(f["evidence"])}</code></div></td>'
        f'<td><div class="rem-text">{esc(f["remediation"])}</div></td></tr>'
        for f in findings
    ) or '<tr class="finding-row" data-sev="info"><td colspan="3" style="text-align:center;padding:32px;color:#94a3b8">No vulnerabilities identified in active scan scope.</td></tr>'

    cards = " ".join(
        f'<div class="card" onclick="filterBySev(\'{s}\')" style="border-top: 3px solid {colors[s]}">'
        f'<div class="n" style="color:{colors[s]};text-shadow:0 0 10px {glows[s]}">{summary["counts"][s]}</div>'
        f'<div class="l" style="color:#94a3b8">{s.upper()}</div></div>'
        for s in SEVERITY_ORDER
    )

    score_val = summary['score']
    score_band = summary['band']
    band_color = colors.get(score_band.lower(), "#38bdf8")
    band_glow = glows.get(score_band.lower(), "rgba(56, 189, 248, 0.4)")

    auditor = meta.get("auditor") or {}
    auditor_card = ""
    if auditor and any(auditor.values()):
        role = auditor.get("role", "Cybersecurity Engineer")
        exp = auditor.get("experience", "—")
        curr_sal = auditor.get("current_salary", "—")
        exp_sal = auditor.get("expected_salary", "—")
        auditor_card = f"""
<div class="hud-box auditor-hud">
  <div class="hud-header">
    <div class="hud-title">
      <span class="pulse-dot"></span>
      <span>CYBERSECURITY OPERATIVE // ASSESSOR PROFILE</span>
    </div>
    <div class="hud-status">STATUS: <span style="color:#10b981;font-weight:700">AUTHORIZED / ACTIVE</span></div>
  </div>
  <div class="auditor-grid">
    <div class="auditor-cell">
      <div class="lbl">OPERATIVE TITLE</div>
      <div class="val highlight">{esc(role)}</div>
    </div>
    <div class="auditor-cell">
      <div class="lbl">PRIOR EXPERIENCE</div>
      <div class="val">{esc(exp)}</div>
    </div>
    <div class="auditor-cell">
      <div class="lbl">CURRENT SALARY / RATE</div>
      <div class="val">{esc(curr_sal)}</div>
    </div>
    <div class="auditor-cell">
      <div class="lbl">EXPECTED SALARY / TARGET</div>
      <div class="val target-glow">{esc(exp_sal)}</div>
    </div>
  </div>
</div>"""

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cyber Audit // {esc(target)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<style>
:root {{
  --bg-dark: #070b14;
  --bg-panel: #0d1527;
  --bg-card: #131f38;
  --border: #1e2e4f;
  --border-focus: #00f2fe;
  --cyan-neon: #00f2fe;
  --cyan-glow: rgba(0, 242, 254, 0.35);
  --emerald: #10b981;
  --text-main: #f1f5f9;
  --text-dim: #94a3b8;
  --text-code: #38bdf8;
}}
* {{ box-sizing: border-box; }}
body {{
  font-family: 'Inter', -apple-system, sans-serif;
  margin: 0;
  background: var(--bg-dark);
  background-image: 
    radial-gradient(circle at 15% 15%, rgba(0, 242, 254, 0.05) 0%, transparent 40%),
    radial-gradient(circle at 85% 85%, rgba(255, 0, 85, 0.04) 0%, transparent 40%),
    linear-gradient(rgba(14, 23, 42, 0.6) 1px, transparent 1px),
    linear-gradient(90deg, rgba(14, 23, 42, 0.6) 1px, transparent 1px);
  background-size: 100% 100%, 100% 100%, 36px 36px, 36px 36px;
  color: var(--text-main);
  min-height: 100vh;
  line-height: 1.5;
}}
.wrap {{
  max-width: 1200px;
  margin: 0 auto;
  padding: 40px 24px;
}}
.top-bar {{
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-bottom: 1px solid var(--border);
  padding-bottom: 20px;
  margin-bottom: 28px;
}}
.brand {{
  display: flex;
  align-items: center;
  gap: 12px;
}}
.brand-icon {{
  width: 36px;
  height: 36px;
  background: linear-gradient(135deg, #00f2fe, #4facfe);
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: #000;
  font-size: 20px;
  font-weight: 800;
  box-shadow: 0 0 16px var(--cyan-glow);
}}
h1 {{
  margin: 0;
  font-size: 26px;
  font-weight: 800;
  letter-spacing: -0.02em;
  background: linear-gradient(90deg, #ffffff, #93c5fd);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}}
.sub {{
  color: var(--text-dim);
  font-size: 13px;
  font-family: 'JetBrains Mono', monospace;
  margin-top: 4px;
}}
.hud-box {{
  background: var(--bg-panel);
  border: 1px solid var(--border);
  border-radius: 14px;
  box-shadow: 0 8px 32px rgba(0,0,0,0.4);
  backdrop-filter: blur(12px);
  margin-bottom: 24px;
}}
.auditor-hud {{
  border-left: 4px solid var(--cyan-neon);
  padding: 20px 24px;
}}
.hud-header {{
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-bottom: 1px solid rgba(255,255,255,0.06);
  padding-bottom: 12px;
  margin-bottom: 16px;
}}
.hud-title {{
  display: flex;
  align-items: center;
  gap: 8px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  letter-spacing: 0.08em;
  color: var(--cyan-neon);
  font-weight: 700;
}}
.pulse-dot {{
  width: 8px;
  height: 8px;
  background: var(--emerald);
  border-radius: 50%;
  box-shadow: 0 0 10px var(--emerald);
  animation: pulse 2s infinite;
}}
@keyframes pulse {{
  0% {{ transform: scale(0.95); opacity: 0.8; }}
  50% {{ transform: scale(1.3); opacity: 1; }}
  100% {{ transform: scale(0.95); opacity: 0.8; }}
}}
.hud-status {{
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px;
  color: var(--text-dim);
}}
.auditor-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 20px;
}}
.auditor-cell .lbl {{
  font-size: 11px;
  font-family: 'JetBrains Mono', monospace;
  color: var(--text-dim);
  letter-spacing: 0.05em;
  margin-bottom: 4px;
}}
.auditor-cell .val {{
  font-size: 16px;
  font-weight: 700;
  color: #fff;
}}
.auditor-cell .val.highlight {{
  color: #38bdf8;
}}
.auditor-cell .val.target-glow {{
  color: #a7f3d0;
  text-shadow: 0 0 12px rgba(16, 185, 129, 0.4);
}}

/* Threat Gauge & Score */
.score-section {{
  display: grid;
  grid-template-columns: 280px 1fr;
  gap: 24px;
  background: var(--bg-panel);
  border: 1px solid var(--border);
  border-radius: 14px;
  padding: 24px;
  margin-bottom: 24px;
  align-items: center;
}}
@media (max-width: 768px) {{
  .score-section {{ grid-template-columns: 1fr; text-align: center; }}
}}
.gauge-box {{
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  position: relative;
}}
.circle-meter {{
  width: 140px;
  height: 140px;
  position: relative;
  display: flex;
  align-items: center;
  justify-content: center;
}}
.circle-inner {{
  position: absolute;
  text-align: center;
}}
.score-number {{
  font-size: 42px;
  font-weight: 900;
  font-family: 'JetBrains Mono', monospace;
  color: {band_color};
  text-shadow: 0 0 16px {band_glow};
  line-height: 1;
}}
.score-max {{
  font-size: 12px;
  color: var(--text-dim);
  font-family: 'JetBrains Mono', monospace;
}}
.band-badge {{
  display: inline-block;
  margin-top: 10px;
  padding: 4px 14px;
  border-radius: 20px;
  font-size: 12px;
  font-weight: 700;
  font-family: 'JetBrains Mono', monospace;
  letter-spacing: 0.05em;
  color: #fff;
  background: {band_color};
  box-shadow: 0 0 14px {band_glow};
}}
.score-info h2 {{
  margin: 0 0 8px;
  font-size: 20px;
  font-weight: 700;
}}
.score-info p {{
  color: var(--text-dim);
  font-size: 14px;
  margin: 0 0 16px;
}}
.scan-meta-tags {{
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}}
.meta-tag {{
  background: var(--bg-card);
  border: 1px solid var(--border);
  padding: 4px 10px;
  border-radius: 6px;
  font-size: 12px;
  font-family: 'JetBrains Mono', monospace;
  color: #cbd5e1;
}}

/* Severity Cards */
.cards {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
  gap: 12px;
  margin-bottom: 24px;
}}
.card {{
  background: var(--bg-panel);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 16px;
  text-align: center;
  cursor: pointer;
  transition: all 0.2s ease;
}}
.card:hover {{
  transform: translateY(-2px);
  border-color: var(--border-focus);
}}
.card .n {{
  font-size: 32px;
  font-weight: 800;
  font-family: 'JetBrains Mono', monospace;
  line-height: 1.1;
}}
.card .l {{
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.08em;
  margin-top: 4px;
}}

/* Console Toolbar */
.toolbar {{
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 16px;
  margin-bottom: 16px;
  flex-wrap: wrap;
}}
.search-box {{
  flex: 1;
  min-width: 260px;
  position: relative;
}}
.search-box input {{
  width: 100%;
  background: var(--bg-panel);
  border: 1px solid var(--border);
  padding: 10px 14px 10px 36px;
  border-radius: 8px;
  color: #fff;
  font-family: 'JetBrains Mono', monospace;
  font-size: 13px;
  outline: none;
  transition: border-color 0.2s;
}}
.search-box input:focus {{
  border-color: var(--cyan-neon);
  box-shadow: 0 0 10px var(--cyan-glow);
}}
.search-box::before {{
  content: '>';
  position: absolute;
  left: 14px;
  top: 10px;
  color: var(--cyan-neon);
  font-family: 'JetBrains Mono', monospace;
  font-weight: 700;
}}
.btn-group {{
  display: flex;
  gap: 8px;
}}
.btn {{
  background: var(--bg-panel);
  border: 1px solid var(--border);
  color: #cbd5e1;
  padding: 8px 14px;
  border-radius: 8px;
  font-size: 12px;
  font-family: 'JetBrains Mono', monospace;
  cursor: pointer;
  transition: all 0.2s;
}}
.btn:hover {{
  border-color: var(--cyan-neon);
  color: #fff;
}}

/* Findings Table */
.table-wrap {{
  background: var(--bg-panel);
  border: 1px solid var(--border);
  border-radius: 14px;
  overflow: hidden;
  box-shadow: 0 8px 32px rgba(0,0,0,0.3);
}}
table {{
  width: 100%;
  border-collapse: collapse;
}}
th {{
  background: #09101f;
  text-align: left;
  padding: 14px 16px;
  font-size: 11px;
  font-family: 'JetBrains Mono', monospace;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--text-dim);
  border-bottom: 1px solid var(--border);
}}
td {{
  padding: 16px;
  border-bottom: 1px solid rgba(255,255,255,0.05);
  vertical-align: top;
  font-size: 14px;
}}
tr.finding-row:hover {{
  background: rgba(255,255,255,0.02);
}}
.sev {{
  color: #fff;
  padding: 4px 10px;
  border-radius: 6px;
  font-size: 10px;
  font-weight: 800;
  font-family: 'JetBrains Mono', monospace;
  letter-spacing: 0.05em;
  display: inline-block;
}}
.title-text {{
  color: #f8fafc;
  font-size: 14px;
  font-weight: 600;
}}
.ev-code {{
  background: #080d1a;
  border: 1px solid rgba(255,255,255,0.08);
  border-radius: 6px;
  padding: 8px 12px;
  margin-top: 8px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  color: var(--text-code);
  word-break: break-all;
}}
.rem-text {{
  color: #cbd5e1;
  font-size: 13px;
}}
footer {{
  margin-top: 32px;
  text-align: center;
  color: #64748b;
  font-size: 12px;
  font-family: 'JetBrains Mono', monospace;
}}
</style>
</head>
<body>
<div class="wrap">
  <div class="top-bar">
    <div class="brand">
      <div class="brand-icon">⬡</div>
      <div>
        <h1>Cyber Audit // External Security Benchmark</h1>
        <div class="sub">TARGET <b>{esc(target)}</b> &middot; CUSTOMER <b>{esc(meta.get('customer','—'))}</b> &middot; {esc(meta.get('started',''))} &middot; PROFILE <b>{esc(meta.get('profile','lite').upper())}</b></div>
      </div>
    </div>
    <div class="meta-tag">ENGINE v{VERSION}</div>
  </div>

  <div class="sub" style="margin-top:-16px;margin-bottom:20px">Modules run: {esc(cov)}</div>

  {auditor_card}

  <div class="score-section">
    <div class="gauge-box">
      <div class="circle-meter">
        <svg viewBox="0 0 100 100" style="transform: rotate(-90deg); width: 100%; height: 100%;">
          <circle cx="50" cy="50" r="40" fill="none" stroke="#1e2e4f" stroke-width="8" />
          <circle cx="50" cy="50" r="40" fill="none" stroke="{band_color}" stroke-width="8"
            stroke-dasharray="251.2"
            stroke-dashoffset="{round(251.2 * (1 - score_val / 100), 1)}"
            stroke-linecap="round"
            style="filter: drop-shadow(0 0 6px {band_glow}); transition: stroke-dashoffset 1s ease;" />
        </svg>
        <div class="circle-inner">
          <div class="score-number">{score_val}</div>
          <div class="score-max">/ 100</div>
        </div>
      </div>
      <div class="band-badge">{score_band.upper()} THREAT LEVEL</div>
    </div>
    <div class="score-info">
      <h2>External Attack Surface Analysis</h2>
      <p>Calculated across {len(findings)} normalized findings using weighted threat vectors. Zero-trust external network posture evaluated.</p>
      <div class="scan-meta-tags">
        <div class="meta-tag">AUTH REF: {esc(meta.get('authorization_reference','—'))}</div>
        <div class="meta-tag">DEFENSE AUDITOR VERIFIED</div>
        <div class="meta-tag">READ-ONLY PROBES</div>
      </div>
    </div>
  </div>

  <div class="cards">{cards}</div>

  <div class="toolbar">
    <div class="search-box">
      <input type="text" id="searchInput" placeholder="Filter vulnerabilities, CVEs, protocols..." onkeyup="filterTable()">
    </div>
    <div class="btn-group">
      <button class="btn" onclick="filterBySev('all')">ALL ({len(findings)})</button>
      <button class="btn" onclick="window.print()">🖨️ PRINT / PDF</button>
    </div>
  </div>

  <div class="table-wrap">
    <table id="findingsTable">
      <thead>
        <tr>
          <th style="width:110px">SEVERITY</th>
          <th>FINDING &amp; EVIDENCE</th>
          <th style="width:380px">REMEDIATION ACTION</th>
        </tr>
      </thead>
      <tbody>
        {rows}
      </tbody>
    </table>
  </div>

  <footer>
    [ CYBER AUDIT DEFENSIVE MATRIX ] &middot; Lead Assessor: {esc(auditor.get('role', 'Cybersecurity Engineer'))} &middot; Scanner Engine v{VERSION}<br>
    Absence of a finding is not proof of absence of a vulnerability. See docs/TEST-PLAN.md.
  </footer>
</div>

<script>
function filterTable() {{
  var q = document.getElementById('searchInput').value.toLowerCase();
  var rows = document.querySelectorAll('#findingsTable tbody tr');
  rows.forEach(function(row) {{
    var txt = row.innerText.toLowerCase();
    row.style.display = txt.indexOf(q) > -1 ? '' : 'none';
  }});
}}

function filterBySev(sev) {{
  var rows = document.querySelectorAll('#findingsTable tbody tr');
  rows.forEach(function(row) {{
    if (sev === 'all' || row.getAttribute('data-sev') === sev) {{
      row.style.display = '';
    }} else {{
      row.style.display = 'none';
    }}
  }});
}}
</script>
</body>
</html>"""


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------

def load_config(path):
    with open(path, encoding="utf-8") as fh:
        cfg = json.load(fh)
    if not cfg.get("i_have_authorization"):
        sys.exit("REFUSING TO RUN: config must set \"i_have_authorization\": true. "
                 "Scanning without written authorization is illegal.")
    allowed = cfg.get("allowed_targets") or []
    if cfg.get("target") not in allowed:
        sys.exit(f"REFUSING TO RUN: target {cfg.get('target')!r} is not in allowed_targets.")
    cfg.setdefault("output_dir", "/app/out")
    cfg.setdefault("timeout_seconds", 60)
    cfg.setdefault("modules", {})
    cfg.setdefault("tls_ports", [443])
    cfg.setdefault("http_ports", [80])
    cfg.setdefault("ssh_port", 22)
    cfg.setdefault("profile", "lite")
    cfg.setdefault("allow_intrusive", False)
    cfg.setdefault("auditor", {})
    return cfg


def load_policy(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except OSError:
        return {}


# Core modules: name -> fn(target, cfg). nmap ports runs first (provides XML).
CORE_MODULES = {
    "ssh": scan_ssh,
    "tls": scan_tls,
    "http": scan_http,
    "https": scan_https,
    "api": scan_api,
    "onpage": scan_onpage,
}


def run(cfg, policy_path, profile=None):
    target = cfg["target"]
    profile = profile or cfg.get("profile", "lite")
    auditor_info = cfg.get("auditor", {})
    role = auditor_info.get("role", "Cybersecurity Engineer")

    print(CYBER_BANNER)
    print(f"\033[96m[>]\033[0m LEAD ASSESSOR : \033[1m{role}\033[0m")
    if auditor_info.get("experience"):
        print(f"\033[96m[>]\033[0m EXPERIENCE    : {auditor_info.get('experience')}")
    print(f"\033[96m[>]\033[0m TARGET        : \033[1m{target}\033[0m (Profile: \033[93m{profile.upper()}\033[0m)")
    print(f"\033[96m[>]\033[0m CLIENT / AUTH : {cfg.get('customer', '-')} (Ref: {cfg.get('authorization_reference', '-')})")
    print("\033[90m" + "-" * 75 + "\033[0m")

    meta = {
        "started": dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        "customer": cfg.get("customer", "-"),
        "authorization_reference": cfg.get("authorization_reference", "-"),
        "scanner": VERSION,
        "profile": profile,
        "auditor": auditor_info,
    }
    policy = load_policy(policy_path)
    modules = cfg["modules"]
    coverage = []

    raw, nmap_xml = [], None
    if modules.get("ports", True):
        print(f"\033[34m[*] Probing TCP attack surface (ports)...\033[0m")
        try:
            f, nmap_xml = scan_ports(target, cfg)
            raw += f
            coverage.append("ports")
        except Exception as e:  # noqa: BLE001
            raw.append(scan_error("ports", e))
    if modules.get("outdated", True):
        print(f"\033[34m[*] Evaluating service CVE baseline vs versions.json...\033[0m")
        try:
            raw += scan_outdated(nmap_xml, cfg, policy)
            coverage.append("outdated")
        except Exception as e:  # noqa: BLE001
            raw.append(scan_error("outdated", e))

    # Core checks
    for name, fn in CORE_MODULES.items():
        if name == "tls" and profile == "deep":
            continue
        if modules.get(name, True):
            print(f"\033[34m[*] Running module: {name} ...\033[0m")
            try:
                raw += fn(target, cfg)
                coverage.append(name)
            except Exception as e:  # noqa: BLE001
                raw.append(scan_error(name, e))

    # Deep profile: heavy tools
    if profile == "deep":
        import deepscan as ds
        for name, fn in ds.DEEP_MODULES.items():
            if modules.get(name, True) is False:
                continue
            print(f"\033[35m[*] Deep probe module: {name} ...\033[0m")
            try:
                if name == "nmap_vuln":
                    raw += fn(target, cfg, nmap_xml)
                else:
                    raw += fn(target, cfg)
                coverage.append(name)
            except Exception as e:  # noqa: BLE001
                raw.append(scan_error(name, e))

    findings = normalize(raw)
    summary = score(findings)

    out_dir = cfg["output_dir"]
    os.makedirs(out_dir, exist_ok=True)
    meta["finished"] = dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    meta["coverage"] = coverage
    report = {"target": target, "meta": meta, "summary": summary, "findings": findings}
    with open(os.path.join(out_dir, "findings.json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    with open(os.path.join(out_dir, "report.html"), "w", encoding="utf-8") as fh:
        fh.write(render_html(target, meta, findings, summary, coverage))

    band_color = "\033[91m" if summary["band"] in ("Critical", "High") else "\033[93m" if summary["band"] == "Moderate" else "\033[92m"
    reset = "\033[0m"
    print("\033[90m" + "-" * 75 + "\033[0m")
    print(f"\033[92m[+]\033[0m ASSESSMENT COMPLETE | {len(findings)} normalized findings.")
    print(f"\033[1m[!] RISK POSTURE : {band_color}{summary['score']}/100 ({summary['band'].upper()} RISK){reset}")
    print(f"\033[96m[+] HTML Report  : \033[1m{out_dir}/report.html\033[0m")
    print(f"\033[96m[+] Raw Findings : \033[1m{out_dir}/findings.json\033[0m")
    print("\033[90m" + "=" * 75 + "\033[0m\n")
    return report


def main(argv=None):
    ap = argparse.ArgumentParser(description="Cyber Audit external security scanner")
    ap.add_argument("--config", required=True, help="path to scan config JSON")
    ap.add_argument("--policy", default="/app/config/versions.json",
                    help="path to outdated-software policy JSON")
    ap.add_argument("--profile", choices=["lite", "deep"], default=None,
                    help="lite = core checks; deep = all tools (overrides config)")
    ap.add_argument("--intrusive", action="store_true",
                    help="enable active nuclei/nmap templates (deep profile only)")
    args = ap.parse_args(argv)
    cfg = load_config(args.config)
    if args.profile:
        cfg["profile"] = args.profile
    if args.intrusive:
        cfg["allow_intrusive"] = True
    run(cfg, args.policy)


if __name__ == "__main__":
    main()
