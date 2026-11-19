import dataclasses
import hashlib
import json
import random
import subprocess
import sys
from datetime import date
from pathlib import Path

import pytest

from triage.core import (Finding, apply_suppressions, dedupe, diff_baseline, fingerprint, gate,
                         load_bandit, load_semgrep_sarif, load_suppressions, normalize_path)

ROOT = Path(__file__).resolve().parent.parent
PROJECT = "diwan_invoicing"
EMPTY_SARIF = {"runs": [{"tool": {"driver": {"rules": []}}, "results": []}]}


def finding(**over):
    base = dict(tool="semgrep", rule_id="r1", path="a.py", line=1, severity="medium",
                cwe=None, message="m", code="x = 1")
    base.update(over)
    return Finding(**base)


def write(tmp_path, name, data):
    p = tmp_path / name
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


def sarif_file(tmp_path, props=None, default_level="warning", level=None):
    rule = {"id": "r1", "properties": props or {}}
    if default_level:
        rule["defaultConfiguration"] = {"level": default_level}
    res = {"ruleId": "r1", "message": {"text": "msg"},
           "locations": [{"physicalLocation": {
               "artifactLocation": {"uri": "./invoicing/web.py"},
               "region": {"startLine": 3, "snippet": {"text": "    x = 1\n    y = 2"}}}}]}
    if level:
        res["level"] = level
    return write(tmp_path, "s.sarif", {"runs": [{"tool": {"driver": {"rules": [rule]}}, "results": [res]}]})


def semgrep_first(p):
    return load_semgrep_sarif(p, PROJECT)[0]


def bandit_result(**over):
    r = {"test_id": "B608", "issue_text": "text", "issue_severity": "MEDIUM", "issue_confidence": "HIGH",
         "issue_cwe": {"id": 89}, "line_number": 10, "filename": "./invoicing/web.py",
         "code": "9 a = 1\n10 b = 2\n11 c = 3\n"}
    r.update(over)
    return r


def bandit_first(tmp_path, **over):
    return load_bandit(write(tmp_path, "b.json", {"results": [bandit_result(**over)]}), PROJECT)[0]


# ---------- Semgrep ----------

@pytest.mark.parametrize("score,expected", [
    (9.0, "critical"), ("9.0", "critical"), (10, "critical"), (7.0, "high"), ("8.9", "high"),
    (4.0, "medium"), ("6.9", "medium"), (3.9, "low"), ("0.1", "low"),
])
def test_security_severity_maps_score(tmp_path, score, expected):
    p = sarif_file(tmp_path, props={"security-severity": score}, level="none")   # level would give info
    assert semgrep_first(p).severity == expected


@pytest.mark.parametrize("bad", [0.0, "abc", 11, "11"])
def test_unusable_score_falls_back_to_level(tmp_path, bad):
    p = sarif_file(tmp_path, props={"security-severity": bad}, level="error")
    assert semgrep_first(p).severity == "high"


def test_level_rules(tmp_path):
    assert semgrep_first(sarif_file(tmp_path, default_level="note", level="error")).severity == "high"
    assert semgrep_first(sarif_file(tmp_path, default_level="note")).severity == "low"
    assert semgrep_first(sarif_file(tmp_path, default_level=None)).severity == "medium"


def test_semgrep_fields(tmp_path):
    f = semgrep_first(sarif_file(tmp_path))
    assert (f.tool, f.rule_id, f.path, f.line, f.code) == ("semgrep", "r1", "invoicing/web.py", 3, "    x = 1")


def test_cwe_from_tags(tmp_path):
    assert semgrep_first(sarif_file(tmp_path, props={"tags": ["x", "CWE-89: SQL", "CWE-79: XSS"]})).cwe == 89
    assert semgrep_first(sarif_file(tmp_path, props={"tags": ["x", "OWASP-A1"]})).cwe is None


def test_two_runs_give_findings_from_both(tmp_path):
    one = sarif_file(tmp_path)
    run = json.loads(one.read_text())["runs"][0]
    p = write(tmp_path, "two.sarif", {"runs": [run, run]})
    assert len(load_semgrep_sarif(p, PROJECT)) == 2


# ---------- Bandit ----------

EXPECTED = {
    "HIGH": {"HIGH": "high", "MEDIUM": "high", "LOW": "medium"},
    "MEDIUM": {"HIGH": "medium", "MEDIUM": "medium", "LOW": "low"},
    "LOW": {"HIGH": "low", "MEDIUM": "low", "LOW": "info"},
    "UNDEFINED": {"HIGH": "info", "MEDIUM": "info", "LOW": "info"},
}


@pytest.mark.parametrize("sev", list(EXPECTED))
@pytest.mark.parametrize("conf", ["HIGH", "MEDIUM", "LOW"])
def test_bandit_severity_and_confidence(tmp_path, sev, conf):
    f = bandit_first(tmp_path, issue_severity=sev, issue_confidence=conf)
    assert f.severity == EXPECTED[sev][conf]


def test_bandit_without_cwe(tmp_path):
    r = bandit_result()
    del r["issue_cwe"]
    p = write(tmp_path, "b.json", {"results": [r]})
    assert load_bandit(p, PROJECT)[0].cwe is None


@pytest.mark.parametrize("line,expected", [(9, "a = 1"), (10, "b = 2"), (100, "c = 3"), (1, "")])
def test_bandit_picks_the_right_code_line(tmp_path, line, expected):
    f = bandit_first(tmp_path, line_number=line, code="9 a = 1\n10 b = 2\n100 c = 3\n")
    assert f.code == expected


def test_bandit_path_and_fields(tmp_path):
    f = bandit_first(tmp_path)
    assert (f.tool, f.rule_id, f.path, f.line, f.cwe, f.code) == ("bandit", "B608", "invoicing/web.py", 10, 89, "b = 2")


# ---------- paths and fingerprints ----------

@pytest.mark.parametrize("raw", [
    "./invoicing/web.py", "diwan_invoicing\\invoicing\\web.py", "invoicing//./web.py", "invoicing/web.py",
    "/home/runner/work/diwan_invoicing/diwan_invoicing/invoicing/web.py",
    "file:///home/runner/work/diwan_invoicing/invoicing/web.py",
    "C:\\Users\\me\\diwan_invoicing\\invoicing\\web.py",
])
def test_normalize_path(raw):
    assert normalize_path(raw, PROJECT) == "invoicing/web.py"


def test_fingerprint_formula_and_stability():
    f = finding(code="  x  =   1\t")
    assert fingerprint(f) == hashlib.sha256(b"semgrep|r1|a.py|x = 1").hexdigest()
    assert fingerprint(dataclasses.replace(f, line=99, code="\t\tx = 1")) == fingerprint(f)
    assert len(fingerprint(f)) == 64


@pytest.mark.parametrize("change", [dict(tool="bandit"), dict(rule_id="r2"), dict(path="b.py"), dict(code="y = 2")])
def test_fingerprint_changes(change):
    assert fingerprint(finding(**change)) != fingerprint(finding())


# ---------- dedupe ----------

def test_same_line_same_cwe_is_one_group():
    a = finding(tool="semgrep", rule_id="sqli", cwe=89, severity="high")
    b = finding(tool="bandit", rule_id="B608", cwe=89, severity="medium")
    (g,) = dedupe([a, b])
    assert (g.key, g.severity, g.tools) == ("CWE-89", "high", ["bandit", "semgrep"])


def test_equivalence_table_merges_without_cwe():
    a = finding(tool="semgrep", rule_id="py.sqli")
    b = finding(tool="bandit", rule_id="B608")
    eq = {"semgrep:py.sqli": "SQLI", "bandit:B608": "SQLI"}
    assert len(dedupe([a, b])) == 2
    assert [g.key for g in dedupe([a, b], eq)] == ["SQLI"]


def test_different_issue_or_line_stays_apart():
    a = finding(tool="bandit", rule_id="B501", cwe=295)
    b = finding(tool="bandit", rule_id="B113", cwe=400)
    c = finding(tool="bandit", rule_id="B501", cwe=295, line=2)
    assert len(dedupe([a, b, c])) == 3


def test_group_order_is_severity_path_line_key():
    fs = [finding(rule_id="a", severity="low", path="z.py"), finding(rule_id="b", severity="high", path="y.py"),
          finding(rule_id="c", severity="high", path="x.py", line=9), finding(rule_id="d", severity="high", path="x.py", line=2)]
    assert [g.findings[0].rule_id for g in dedupe(fs)] == ["d", "c", "b", "a"]


def test_dedupe_is_deterministic_and_loses_nothing():
    rng = random.Random(7)
    fs = [finding(tool=rng.choice(["semgrep", "bandit"]), rule_id=f"r{rng.randint(1, 3)}", cwe=rng.choice([None, 89]),
                  path=rng.choice(["a.py", "b.py"]), line=rng.randint(1, 3),
                  severity=rng.choice(["low", "high", "critical"]), code=f"c{rng.randint(1, 3)}") for _ in range(40)]

    def summary(groups):
        return [(g.key, g.path, g.line, g.severity, g.tools, g.fingerprints) for g in groups]

    first = dedupe(fs)
    assert sum(len(g.findings) for g in first) == len(fs)
    for _ in range(3):
        rng.shuffle(fs)
        assert summary(dedupe(fs)) == summary(first)


# ---------- suppressions, baseline, gate ----------

FP = "a" * 64


def entry(**over):
    e = {"fingerprint": FP, "reason": "accepted risk, ticket 123", "expires": "2026-12-31", "by": "heba"}
    e.update(over)
    return e


def test_valid_and_invalid_suppressions():
    bad = [entry(reason="short"), entry(by=""), entry(by="  "), entry(fingerprint="A" * 64),
           entry(fingerprint="a" * 63), entry(expires="nope"), entry(expires="2026-13-45")]
    missing_by = entry()
    del missing_by["by"]
    missing_date = entry()
    del missing_date["expires"]
    valid, invalid = load_suppressions([entry()] + bad + [missing_by, missing_date])
    assert len(valid) == 1 and len(invalid) == len(bad) + 2


def test_suppression_lasts_through_its_expiry_day():
    g = dedupe([finding()])
    valid, _ = load_suppressions([entry(fingerprint=fingerprint(finding()), expires="2026-11-20")])
    assert apply_suppressions(g, valid, date(2026, 11, 20)) == ([], g)
    assert apply_suppressions(g, valid, date(2026, 11, 21)) == (g, [])


def test_one_suppressed_member_hides_the_merged_group():
    a = finding(tool="semgrep", rule_id="sqli", cwe=89)
    b = finding(tool="bandit", rule_id="B608", cwe=89)
    groups = dedupe([a, b])
    valid, _ = load_suppressions([entry(fingerprint=fingerprint(b), expires="2999-01-01")])
    active, suppressed = apply_suppressions(groups, valid, date(2026, 11, 20))
    assert active == [] and len(suppressed) == 1


def test_baseline_new_existing_fixed():
    groups = dedupe([finding(rule_id="moved", line=5), finding(rule_id="fresh", line=9)])
    baseline = {fingerprint(finding(rule_id="moved", line=1)), "f" * 64, "0" * 64}
    new, existing, fixed = diff_baseline(groups, baseline)
    assert [g.findings[0].rule_id for g in new] == ["fresh"]
    assert [g.findings[0].rule_id for g in existing] == ["moved"]
    assert fixed == ["0" * 64, "f" * 64]


def groups_with(*severities):
    return dedupe([finding(rule_id=f"r{i}", line=i, severity=s) for i, s in enumerate(severities)])


@pytest.mark.parametrize("fail_on,passed", [("low", False), ("medium", False), ("high", False), ("critical", True)])
def test_gate_thresholds(fail_on, passed):
    assert gate(groups_with("low", "high"), fail_on) is passed


def test_gate_edges():
    assert gate([], "info") is True
    assert gate(groups_with("medium"), "high") is True


# ---------- CLI ----------

def run_cli(*args):
    return subprocess.run([sys.executable, "-m", "triage", *map(str, args)], cwd=ROOT,
                          capture_output=True, text=True, timeout=30)


def test_cli_exit_codes_and_keys(tmp_path):
    s = write(tmp_path, "s.sarif", EMPTY_SARIF)
    clean = write(tmp_path, "clean.json", {"results": []})
    dirty = write(tmp_path, "dirty.json", {"results": [bandit_result(issue_severity="HIGH")]})
    junk = tmp_path / "junk.json"
    junk.write_text("not json")

    ok = run_cli("--sarif", s, "--bandit", clean, "--project", PROJECT)
    assert ok.returncode == 0
    assert set(json.loads(ok.stdout)) == {"passed", "new", "existing", "suppressed", "fixed", "invalid_suppressions"}
    assert run_cli("--sarif", s, "--bandit", dirty, "--project", PROJECT).returncode == 1
    assert run_cli("--sarif", s, "--bandit", dirty, "--project", PROJECT, "--fail-on", "critical").returncode == 0
    assert run_cli("--sarif", s, "--bandit", tmp_path / "missing.json", "--project", PROJECT).returncode == 2
    assert run_cli("--sarif", s, "--bandit", junk, "--project", PROJECT).returncode == 2


def test_cli_suppression_end_to_end(tmp_path):
    s = write(tmp_path, "s.sarif", EMPTY_SARIF)
    b = write(tmp_path, "b.json", {"results": [bandit_result(issue_severity="HIGH")]})
    fp = fingerprint(load_bandit(b, PROJECT)[0])
    sup = write(tmp_path, "sup.json", [entry(fingerprint=fp, expires="2999-01-01"), entry(reason="x")])
    r = run_cli("--sarif", s, "--bandit", b, "--project", PROJECT, "--suppressions", sup, "--today", "2026-11-20")
    out = json.loads(r.stdout)
    assert r.returncode == 0 and out["passed"] is True
    assert len(out["suppressed"]) == 1 and out["invalid_suppressions"] == 1