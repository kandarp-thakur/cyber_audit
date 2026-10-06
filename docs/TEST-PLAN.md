# Test Plan — Cyber Audit External Security Scanner

**Version:** 1.1
**Date:** 2026-10-01
**Scope of this document:** how a cyber-audit scan is planned, executed, and
reported, and the safety rules that govern it. Covers both the `lite` (core)
and `deep` (core + heavy tooling) profiles.

---

## 1. Objective

Provide a repeatable, benchmark-based external security assessment of a
customer host: enumerate exposed services, compare them against known-safe
baselines, run community vulnerability templates and configuration audits, and
deliver a summary report of risks with remediation guidance.

Two profiles select how far the assessment goes:

- **`lite`** — core, fast, low-noise checks only (ports, banners, outdated
  software, SSH, TLS, HTTP headers).
- **`deep`** — everything in `lite` plus nuclei, nikto, whatweb, nmap vuln
  scripts, testssl.sh, DNS/email recon, exposed-service probes, container API
  probes, and (optionally) ScoutSuite cloud configuration audit.

## 2. Authorization & Rules of Engagement (MANDATORY)

A scan MUST NOT run without all of the following. The tool enforces these in
code, but the operator is responsible for the paperwork.

| Requirement | Enforced by |
|-------------|-------------|
| Written authorization from the target owner | `"i_have_authorization": true` in config |
| Target explicitly listed | `allowed_targets` allow-list in config |
| Defined scan window | Operator (run only in agreed window) |
| Scope boundary (hosts/ports) | `target` + `ports` in config |
| Point of contact for incidents | Operator (recorded in report metadata) |

**Prohibited:** exploitation, brute-force, denial of service, data modification,
scanning hosts outside the allow-list, scanning outside the agreed window.

## 3. Scope

### In scope
- External TCP port exposure and service identification.
- Service/software version banners and comparison to a minimum-safe baseline.
- SSH server configuration hardening (algorithms, protocol).
- TLS certificate validity, supported protocol versions, and HTTPS redirect/cookie flags.
- HTTP security headers and server banner leakage.
- API testing: documentation/schema exposure, CORS misconfigurations, dangerous HTTP methods.
- On-page testing: plaintext password forms, missing Anti-CSRF tokens, mixed content, client-side secret leaks.
- Lead Auditor / Cybersecurity Engineer metadata in audit reports.

### Out of scope
- Authenticated / credentialed scanning.
- Application-layer logic flaws (XSS, SQLi, auth bypass).
- Social engineering, phishing, physical access.
- Internal network scanning and lateral movement.
- Denial-of-service style load testing.

## 4. Methodology

1. **Reconnaissance** — TCP port sweep of the configured port list.
2. **Service/version identification** — probe open ports, capture banners.
3. **Baseline comparison** — compare detected versions to
   `config/versions.json` minimum-safe versions.
4. **Targeted checks** — SSH audit on the SSH port; TLS/cert check on TLS
   ports; HTTP header check on web ports.
5. **Deep checks** *(profile = `deep`)* — nuclei templates, nikto, whatweb,
   nmap vuln scripts, testssl.sh, DNS/email recon (SPF/DMARC/AXFR), exposed
   database probes, and container API probes. Run only after the core pass.
6. **Cloud audit** *(optional)* — ScoutSuite against read-only cloud
   credentials, when `cloud.provider` is set.
7. **Normalization** — all module output mapped to the common finding schema.
8. **Scoring** — severity weighting → risk score and severity counts.
9. **Reporting** — summary HTML report + machine-readable `findings.json`,
   including which modules were run (coverage).

## 5. Check Matrix

| ID | Check | Tool | Severity basis |
|----|-------|------|----------------|
| PORT-OPEN | Unexpected exposed port | nmap | by port risk class |
| SVC-BANNER-LEAK | Service reveals full version string | nmap | low |
| SVC-OUTDATED | Version below safe baseline | banner vs policy | high/medium |
| SSH-PROTO | SSH protocol/algorithm weakness | ssh-audit | high/medium |
| SSH-CONFIG | SSH allows password/root login | ssh-audit | high |
| TLS-CERT | TLS cert expired / expiring / self-signed | stdlib ssl | high/medium |
| TLS-PROTO | TLS < 1.2 still supported | stdlib ssl | high |
| HTTP-HDR | Missing security headers | stdlib urllib | medium/low |
| SCAN-ERROR | A module failed to complete | internal | info |

### Deep profile additions

| ID | Check | Tool | Severity basis |
|----|-------|------|----------------|
| NUCLEI-* | CVE / misconfig / exposure templates | nuclei | template severity |
| NIKTO-* | Web server misconfigs / known files | nikto | medium |
| WEBTECH-* | Web technology fingerprint | whatweb | info |
| NMAP-VULN-* | Known service CVEs | nmap `--script vuln` | high |
| TLS-*-* | Full TLS/cipher/cert issues | testssl.sh | by testssl severity |
| DNS-SPF / DNS-DMARC | Missing email authentication | dig | medium |
| DNS-AXFR | Zone transfer allowed | dig | high |
| EXPOSED-* | Exposed database services | TCP probe | high |
| CONTAINER-* | Exposed Docker/K8s API | HTTP probe | critical/high |
| SCOUT-* | Cloud configuration (IAM/storage/network/logging) | ScoutSuite | rule level 1-5 |

**Note:** the `cloud` module is a different test category — it uses read-only
cloud API credentials (AWS/Azure/GCP) rather than scanning the target host.
It is skipped unless `cloud.provider` is set.

## 6. Severity Model

| Severity | Weight | Meaning |
|----------|--------|---------|
| critical | 10 | Directly exploitable, immediate risk |
| high | 7 | Serious, likely exploitable |
| medium | 4 | Real weakness, needs conditions |
| low | 2 | Hardening / informational |
| info | 0 | No risk, context only |

**Risk score:** `min(100, sum(weights) * 100 / 40)` — 40 weight units = full
score. Reported with a band: 0–24 Low, 25–49 Moderate, 50–74 High, 75–100 Critical.

## 7. Entry / Exit Criteria

**Entry:** authorization recorded; config valid; target reachable; tools present.
**Exit:** all enabled modules completed or logged as `scan-error`; report
rendered; `findings.json` written.

## 8. Deliverables

- `out/report.html` — customer-facing summary report.
- `out/findings.json` — machine-readable findings.
- Scan metadata: target, start/end time, modules run, tool versions.

## 9. Test-Tool Verification (of the scanner itself)

- `selftest.py` — assert-based smoke test, 11 checks, run in CI / before
  delivery:
  1. finding schema shape
  2. version comparison (`_version_lt`)
  3. normalizer dedupe + severity ordering
  4. severity scoring bands
  5. outdated-software detection against the policy
  6. HTML report rendering
  7. nuclei command is safe by default (excludes `dos`/`fuzz`, no `-interactsh`)
  8. deep-module registry contents (includes `cloud`)
  9. ScoutSuite level mapping + no-op when no provider is set
  10. exposed-service probe skips closed ports
  11. authorization gate refuses to run without `i_have_authorization`
- Run: `python -m py_compile audit.py deepscan.py selftest.py && python selftest.py`
- Manual run against a lab target to confirm each module produces expected
  findings.

## 10. Limitations

- External view only; cannot see internal services or host-level config.
- Version detection depends on banner accuracy; backported patches in a distro
  may not be reflected in the version string (false positives possible).
- Absence of a finding is not proof of absence of a vulnerability.
- The `cloud` (ScoutSuite) module is a separate category: it audits cloud
  configuration via credentials, not the host network surface.
- Authenticated/credentialed application testing and adversarial exploitation
  remain out of scope even in the `deep` profile.
