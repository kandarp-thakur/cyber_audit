# Cyber Audit — Security Benchmark Scanner (Design)

**Date:** 2026-10-01
**Status:** Approved — updated for lite/deep profiles, nuclei, ScoutSuite

## Purpose

A Docker-packaged security scanner. Point it at a customer host/IP; it probes
the target over the network using open-source tooling plus Python stdlib, and
produces a summary HTML report of security findings for the customer. A deep
profile orchestrates best-in-class scanners (nuclei, nikto, testssl.sh, nmap
NSE, ScoutSuite) so coverage is large without hand-writing checks.

## Scope (decided)

- **Mode:** External network scan (default). Plus an optional cloud-config audit
  (ScoutSuite) that uses read-only API credentials. No on-host file access, no
  agent.
- **Profiles:** `lite` (core checks) and `deep` (core + all heavy tools).
- **Checks (core set):** open ports, service/version banners, SSH hardening,
  TLS/certificate, HTTP security headers, outdated software (node/openssl/nginx).
- **Checks (deep additions):** nuclei templates, nikto, whatweb, nmap `--script
  vuln`, testssl.sh, DNS/email (SPF/DMARC/AXFR), exposed databases, exposed
  Docker/K8s API, and ScoutSuite cloud configuration audit.
- **Report:** Summary — risk score, severity counts, one line per finding with a
  one-line remediation, plus the list of modules run. HTML output.

## Non-goals (YAGNI)

No plugin framework, no database, no web UI, no PDF, no exploitation code. Each
can be added later without reshaping the core.

## Architecture

One Docker image. One Python entrypoint plus a deep-module file.

```
config/<target>.json  ──▶  audit.py (CLI, profile switch)
                              │
                              ├─ safety gate (authorization + allow-list)
                              ├─ CORE: ports/banners (nmap), ssh (ssh-audit),
                              │        tls (ssl), http (urllib),
                              │        outdated (banners vs versions.json)
                              ├─ DEEP (deepscan.py): nuclei, nikto, whatweb,
                              │        nmap --script vuln, testssl,
                              │        dns, services, container, cloud(ScoutSuite)
                              │
                              ▼
                         normalizer ──▶ dedupe ──▶ severity scoring ──▶ risk score
                              │
                              ▼
                         report.html  (summary + coverage)
                         findings.json (machine-readable)
```

### Components

| File | Responsibility |
|------|----------------|
| `Dockerfile` | Debian slim + nmap + ssh-audit + nuclei + nikto + testssl.sh + whatweb + ScoutSuite + python3 |
| `audit.py` | CLI, safety gate, core modules, profile orchestration, normalizer, scoring, report |
| `deepscan.py` | Deep-module wrappers (tool → finding schema), `DEEP_MODULES` registry |
| `config/example.config.json` | Target, profile, ports, module toggles, nuclei/cloud blocks, authorization |
| `config/versions.json` | Outdated-software policy (min safe versions) |
| `docs/TEST-PLAN.md` | Test planning: scope, method, check matrix, safety |
| `README.md` | How to run on a customer server |

Each module is a function `scan_<name>(target, config) -> list[Finding dict]`.
Modules are independent and return the common schema; the normalizer only
validates/dedupes/scores. Adding a tool = one function + one `DEEP_MODULES` line.

### Finding schema (single schema for all modules)

```json
{
  "id": "SSH-WEAK-KEX",
  "title": "SSH offers weak key exchange algorithms",
  "severity": "high",
  "evidence": "kex: diffie-hellman-group1-sha1",
  "remediation": "Disable legacy KEX in sshd_config (KexAlgorithms ...)"
}
```

### Data flow

1. Load config; run safety gate.
2. Run each enabled module; collect raw findings.
3. Normalize (validate schema, drop malformed), dedupe by `id`+`evidence`.
4. Score: map severity → weight, compute 0–100 risk score and severity counts.
5. Render `report.html` + write `findings.json` into the mounted output dir.

### Error handling

- A module that raises or whose external tool is missing is recorded as a
  `scan-error` finding (severity `info`) — one bad module never aborts the run.
- Non-open ports / unreachable services are skipped silently (not findings).
- A module that finds nothing reports "no issues" in its section.

## Security & Safety

- **Authorization gate (hard):** the run refuses to start unless config has
  `"i_have_authorization": true` and the target is in `allowed_targets`.
  Prevents accidental scanning of third-party hosts.
- Scanner is read-only: no exploitation, no writes, no DoS payloads.
- **Nuclei safe mode (default):** validated by selftest.
  - `dos` and `fuzz` templates are never run (no override).
  - `intrusive` / `brute-force` tags require `--intrusive`.
  - Out-of-band (interactsh) callbacks are disabled unless `allow_oob: true`.
- **Cloud audit** uses read-only API credentials, mounted read-only; skipped
  entirely when `cloud.provider` is null.
- Container runs as non-root.

## Testing

- Assert-based smoke test (`selftest.py`, 11 checks): finding schema, version
  comparison, normalizer dedupe/order, severity scoring bands, outdated
  detection, report rendering, the authorization gate, the deep-module registry,
  nuclei safe-mode command construction, and ScoutSuite level mapping/no-op.
  No framework, no network. Run: `python3 selftest.py`.
- Manual run against a local test target to verify each module.

## Deployment

Two profiles; run with the config and an output dir mounted:

```
# lite — core checks
docker run --rm -v "$PWD/config:/app/config:ro" -v "$PWD/out:/app/out" \
  cyber-audit --config /app/config/target.json --profile lite

# deep — all tools (--intrusive for active nuclei/nmap templates)
docker run --rm -v "$PWD/config:/app/config:ro" -v "$PWD/out:/app/out" \
  cyber-audit --config /app/config/target.json --profile deep
```

For a cloud audit, also mount read-only credentials and set `cloud.provider`.
The customer receives `out/report.html`.
