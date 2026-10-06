# Cyber Audit

A Docker-packaged **external** security scanner. Point it at an authorized
host/IP; it probes the target over the network using open-source tooling and
Python stdlib, then writes a summary report for the customer.

> ⚠️ **Authorization required.** Only scan hosts you own or have **written
> permission** to test. The tool refuses to run unless the config sets
> `"i_have_authorization": true` and the target is in `allowed_targets`.
> Scanning without authorization is illegal. See [`docs/TEST-PLAN.md`](docs/TEST-PLAN.md).

## Profiles

| Profile | What runs |
|---------|-----------|
| `lite` | Core checks only — fast, few requests |
| `deep` | Core + every heavy tool below — thorough, slow |

## What it checks

**Core (both profiles)**

| Check | Tool |
|-------|------|
| Open TCP ports + service banners | nmap |
| Outdated software (node/openssl/nginx/…) | banner vs `config/versions.json` |
| SSH hardening (weak algorithms, banner) | ssh-audit |
| TLS certificate + protocol version | Python `ssl` (lite only) |
| HTTP security headers + server banner | Python `urllib` |
| HTTPS redirect & cookie audit | Python `urllib` + `ssl` |
| API testing (docs, CORS, methods, leaks) | Python `urllib` |
| On-page HTML audit (CSRF, secrets, mixed content) | Python `html.parser` |

**Deep profile only**

| Check | Tool |
|-------|------|
| 6000+ CVE/misconfig templates | nuclei |
| Web server misconfigs / known files | nikto |
| Web tech fingerprinting | whatweb |
| Known service CVEs | nmap `--script vuln` |
| Full TLS/cipher/cert audit | testssl.sh |
| SPF / DMARC / zone-transfer | dig |
| Exposed MySQL/Postgres/Mongo/Redis | TCP probe |
| Exposed Docker/Kubernetes API | HTTP probe |
| Cloud config (AWS/Azure/GCP) | ScoutSuite |

External view only: no exploitation by default, no writes, read-only. Active
templates require `--intrusive` **and** authorization.

## Build

```sh
cd cyber-audit
docker build -t cyber-audit .
```

## Run

1. Copy the example config and edit it:

   ```sh
   cp config/example.config.json config/target.json
   ```

   Set `target`, add it to `allowed_targets`, set `"i_have_authorization": true`,
   then set `customer`, `ports`, `tls_ports`, `http_ports`, `modules`.

2. Run the scan, mounting the config read-only and an output directory:

   ```sh
   # lite (core checks)
   docker run --rm \
     -v "$PWD/config:/app/config:ro" \
     -v "$PWD/out:/app/out" \
     cyber-audit --config /app/config/target.json --profile lite

   # deep (all tools) — add --intrusive for active nuclei/nmap templates
   docker run --rm \
     -v "$PWD/config:/app/config:ro" \
     -v "$PWD/out:/app/out" \
     cyber-audit --config /app/config/target.json --profile deep
   ```

3. Collect the deliverables from `out/`:

   - `report.html` — customer-facing summary report
   - `findings.json` — machine-readable findings

## Verify the tool itself

```sh
python3 selftest.py
```

Runs assert-based checks on the normalizer, version comparison, scoring,
outdated detection, report rendering and the authorization gate.

## Configuration reference

`config/example.config.json`:

| Key | Meaning |
|-----|---------|
| `target` | Host/IP to scan (must be in `allowed_targets`) |
| `allowed_targets` | Hard allow-list — the safety boundary |
| `i_have_authorization` | Must be `true` or the run aborts |
| `authorization_reference` | Your SOW / ticket id (shown in the report) |
| `customer` | Customer name shown in the report |
| `ports` | nmap port list for the sweep |
| `ssh_port` / `tls_ports` / `http_ports` | Which ports each module targets |
| `profile` | `lite` or `deep` (CLI `--profile` overrides) |
| `allow_intrusive` | Allow active nuclei/nmap vuln templates (default false) |
| `domain` | Domain for DNS/email checks (deep profile) |
| `modules` | Toggle any module: `ports`, `ssh`, `tls`, `http`, `outdated`, `nuclei`, `nikto`, `whatweb`, `nmap_vuln`, `testssl`, `dns`, `services`, `container` |
| `output_dir` | Where `report.html` / `findings.json` are written |

`config/versions.json` holds the minimum-safe software versions and the
remediation text used when a version is below baseline.

### Nuclei options

Nuclei is the workhorse for "test everything" — YAML templates cover CVEs,
misconfigs, exposures and tech detection. Configure it under the `nuclei` block:

| Key | Meaning |
|-----|---------|
| `severity` | Which severities to report (default all) |
| `tags` / `exclude_tags` | Include/exclude template tags (safe sets applied by default) |
| `templates` | Paths to custom template dirs/files |
| `rate_limit` / `concurrency` | How hard to hit the target — lower = gentler |
| `timeout` / `retries` | Per-request timeout and retry count |
| `headers` | Extra request headers (e.g. auth, custom UA) |
| `allow_oob` | Allow out-of-band (interactsh) callbacks — off by default |
| `update_templates` | Pull latest community templates before scanning |
| `extra_args` | Escape hatch for any new nuclei flag |

Safety: `dos` and `fuzz` templates are **never** run; `intrusive`/`brute-force`
tags require `--intrusive`; out-of-band callbacks are disabled unless opted in.

### Cloud audit (ScoutSuite)

ScoutSuite audits a cloud account's configuration (IAM, storage, network, logging…)
using **read-only API credentials** — it is a different category from the network
scans above. Enable it by setting the `cloud` block; it is skipped when
`provider` is `null`.

| Key | Meaning |
|-----|---------|
| `provider` | `aws`, `azure` or `gcp` (null = skip) |
| `profile` | Named credentials profile |
| `regions` / `services` | Limit the audit scope |
| `report_dir` | Where ScoutSuite writes its JSON report |
| `budget` | Timeout multiplier for the cloud audit |

Provide credentials the usual way for the chosen provider — mount a read-only
credentials file or pass environment variables into the container:

```sh
docker run --rm \
  -v "$PWD/config:/app/config:ro" \
  -v "$PWD/out:/app/out" \
  -v "$HOME/.aws:/home/auditor/.aws:ro" \
  cyber-audit --config /app/config/target.json --profile deep
```

ScoutSuite findings are mapped into the same report under the `SCOUT-*` ids.

Custom templates can be bundled by mounting a directory and listing it in
`templates`, so customer-specific checks live as YAML — no code changes.

## Severity model

critical=10 · high=7 · medium=4 · low=2 · info=0 → risk score = weighted total
scaled so 40 units = 100, capped. Bands: 0–24 Low, 25–49 Moderate, 50–74 High,
75–100 Critical.

## Limitations

- External view only; you have a vulnerability if you want an internal one — out of scope.
- Banner-based version detection can produce false positives on distro backports.
- Absence of a finding is not proof of absence of a vulnerability.
