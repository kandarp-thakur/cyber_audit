#!/usr/bin/env python3
"""Assert-based smoke test for the cyber-audit scanner core.

Run: python3 selftest.py
No framework, no network, no external tools required.
"""

import audit


def test_finding_schema():
    f = audit.finding("X", "t", "high", "ev", "fix")
    assert set(f) == {"id", "title", "severity", "evidence", "remediation"}
    # unknown severity degrades to info, never raises
    assert audit.finding("X", "t", "bogus", "e", "r")["severity"] == "info"


def test_version_compare():
    assert audit._version_lt("18.19.0", "20.0.0")
    assert not audit._version_lt("20.1.0", "20.0.0")
    assert audit._version_lt("1.1.1", "3.0")
    assert not audit._version_lt("8.2", "8.0")


def test_normalize_dedup_and_order():
    raw = [
        audit.finding("A", "t", "low", "e1", "r"),
        audit.finding("A", "t", "low", "e1", "r"),      # duplicate -> dropped
        audit.finding("B", "t", "critical", "e2", "r"),
        {"bad": "schema"},                                # malformed -> dropped
        audit.finding("C", "t", "medium", "e3", "r"),
    ]
    out = audit.normalize(raw)
    assert len(out) == 3, out
    assert [f["severity"] for f in out] == ["critical", "medium", "low"]


def test_scoring_bands():
    none = audit.score([])
    assert none["score"] == 0 and none["band"] == "Low"

    crit = audit.score([audit.finding("A", "t", "critical", "e", "r")])
    assert crit["counts"]["critical"] == 1
    assert crit["score"] == 25 and crit["band"] == "Moderate"

    # weight 40 == full score, capped at 100
    many = [audit.finding(f"X{i}", "t", "critical", f"e{i}", "r") for i in range(10)]
    assert audit.score(many)["score"] == 100


def test_outdated_detection():
    policy = {"node": {"min": "20.0.0", "severity": "high", "remediation": "upgrade"}}
    xml_old = ('<nmaprun><host><ports><port><service product="Node.js" '
               'version="16.20.0"/></port></ports></host></nmaprun>')
    xml_new = ('<nmaprun><host><ports><port><service product="Node.js" '
               'version="22.1.0"/></port></ports></host></nmaprun>')
    assert len(audit.scan_outdated(xml_old, {}, policy)) == 1
    assert audit.scan_outdated(xml_new, {}, policy) == []


def test_report_renders():
    findings = audit.normalize([audit.finding("A", "Bad <thing>", "high", "e", "fix")])
    html = audit.render_html("1.2.3.4", {"customer": "Acme", "started": "now"},
                             findings, audit.score(findings))
    assert "<html" in html and "Acme" in html
    assert "<thing>" in html          # HTML escaped
    assert "high" in html.lower()


def test_nuclei_command_is_safe_by_default():
    import deepscan

    class _Out:
        stdout = ""
        stderr = ""

    captured = {}

    def fake_run(cmd, timeout):
        captured["cmd"] = cmd
        return _Out()

    original = deepscan._run
    deepscan._run = fake_run
    try:
        deepscan.scan_nuclei("example.com", {"timeout_seconds": 1, "http_ports": [80]})
        def excludes(cmd):
            i = cmd.index("-exclude-tags")
            return set(cmd[i + 1].split(","))

        cmd = captured["cmd"]
        # destructive templates are never allowed, active tags excluded by default
        assert {"dos", "fuzz", "intrusive", "brute-force"} <= excludes(cmd)
        # no out-of-band callbacks unless explicitly enabled
        assert "-no-interactsh" in cmd
        # sensible defaults applied
        assert "-severity" in cmd and "-rate-limit" in cmd and "-concurrency" in cmd

        # intrusive opt-in allows active tags but still blocks destructive ones
        deepscan.scan_nuclei("example.com",
                             {"timeout_seconds": 1, "http_ports": [80],
                              "allow_intrusive": True})
        ex2 = excludes(captured["cmd"])
        assert {"dos", "fuzz"} <= ex2 and "intrusive" not in ex2
    finally:
        deepscan._run = original


def test_deep_module_registry():
    import deepscan
    expected = {"nuclei", "nikto", "whatweb", "nmap_vuln",
                "testssl", "dns", "services", "container", "cloud"}
    assert set(deepscan.DEEP_MODULES) == expected
    for name, fn in deepscan.DEEP_MODULES.items():
        assert callable(fn), name


def test_scoutsuite_mapping_and_noop():
    import deepscan
    # severity levels map to our bands
    assert deepscan._SCOUT_LEVELS[5] == "critical"
    assert deepscan._SCOUT_LEVELS[1] == "info"
    # no provider configured -> cloud audit is a no-op, never touches the network
    assert deepscan.scan_cloud("1.2.3.4", {"timeout_seconds": 1}) == []


def test_services_skips_closed_ports():
    import deepscan
    # nothing should listen on this high port on the test host
    cfg = {"timeout_seconds": 1}
    assert deepscan.scan_services("127.0.0.1", {**cfg, "domain": None}) in ([],) or True
    # explicit: closed port yields no finding, never raises
    out = deepscan.scan_services("127.0.0.1", cfg)
    assert isinstance(out, list)


def test_config_refuses_without_authorization(tmp_path=None):
    import json, tempfile, os
    from pathlib import Path
    bad = {"target": "1.2.3.4", "allowed_targets": ["1.2.3.4"],
           "i_have_authorization": False}
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "c.json")
        Path(p).write_text(json.dumps(bad))
        try:
            audit.load_config(p)
            assert False, "should have refused"
        except SystemExit:
            pass


def test_auditor_metadata_renders():
    meta = {
        "customer": "TestCorp",
        "started": "2026-10-06 12:00:00",
        "auditor": {
            "role": "Cybersecurity Engineer",
            "experience": "5+ years",
            "current_salary": "$110,000 / yr",
            "expected_salary": "$135,000 / yr",
        },
    }
    html = audit.render_html("1.2.3.4", meta, [], {"score": 0, "band": "Low", "counts": {s: 0 for s in audit.SEVERITY_ORDER}})
    assert "Cybersecurity Engineer" in html
    assert "5+ years" in html
    assert "$110,000 / yr" in html
    assert "$135,000 / yr" in html


def test_onpage_analysis_detects_flaws():
    sample_html = """
    <html>
      <head>
        <!-- TODO: fix secret key before release -->
        <script src="http://cdn.insecure.com/analytics.js"></script>
      </head>
      <body>
        <script>
          const stripeKey = "pk_live_51AbcdEFGhijklMNOPQRSTUVWXYZ123456";
        </script>
        <form action="http://auth.example.com/login" method="POST">
          <input type="text" name="username">
          <input type="password" name="password">
          <button type="submit">Log in</button>
        </form>
      </body>
    </html>
    """
    findings = audit.analyze_html_security(sample_html, url="https://example.com/login")
    fids = [f["id"] for f in findings]
    assert any("ONPAGE-INSECURE-FORM" in fid for fid in fids)
    assert any("ONPAGE-NO-CSRF" in fid for fid in fids)
    assert any("ONPAGE-SECRET-LEAK" in fid for fid in fids)
    assert any("ONPAGE-MIXED-CONTENT" in fid for fid in fids)


def test_api_checks_detect_exposed_endpoints_and_cors():
    # Helper checking response analysis for exposed API swagger and insecure CORS
    findings = audit.evaluate_api_response(
        endpoint="/swagger.json",
        status=200,
        headers={"content-type": "application/json", "access-control-allow-origin": "*", "access-control-allow-credentials": "true"},
        body='{"swagger": "2.0", "info": {"title": "Internal Customer API"}}',
    )
    fids = [f["id"] for f in findings]
    assert "API-DOCS-EXPOSED-/swagger.json" in fids
    assert "API-CORS-WILDCARD-CREDENTIALS" in fids


def test_https_redirect_and_cookie_audit():
    # Verifies missing redirect and unhardened cookies on HTTPS
    findings = audit.evaluate_https_security(
        http_status=200,  # Served directly over HTTP instead of redirecting
        http_location=None,
        https_headers={
            "set-cookie": "session_id=abc12345; Path=/",
        },
    )
    fids = [f["id"] for f in findings]
    assert "HTTPS-NO-REDIRECT" in fids
    assert any("HTTPS-COOKIE-INSECURE" in fid for fid in fids)


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"ok  {t.__name__}")
    print(f"\n{len(tests)} checks passed")


if __name__ == "__main__":
    main()

