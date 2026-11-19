"""triage: merge Semgrep and Bandit findings and gate the build on new ones."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import date

SEVERITIES = ["info", "low", "medium", "high", "critical"]   # lowest to highest


@dataclass(frozen=True)
class Finding:
    tool: str            # "semgrep" or "bandit"
    rule_id: str
    path: str            # normalised
    line: int
    severity: str        # one of SEVERITIES
    cwe: int | None
    message: str
    code: str            # the source text of the finding's line, as reported by the tool


@dataclass
class Group:
    key: str
    path: str
    line: int
    severity: str        # the highest severity among its findings
    findings: list[Finding] = field(default_factory=list)

    @property
    def tools(self) -> list[str]:
        return sorted({f.tool for f in self.findings})

    @property
    def fingerprints(self) -> list[str]:
        return sorted({fingerprint(f) for f in self.findings})


@dataclass(frozen=True)
class Suppression:
    fingerprint: str
    reason: str
    expires: date
    by: str


# ---------- paths and fingerprints ----------

def normalize_path(raw: str, project: str) -> str:
    p = raw.replace("\\", "/")
    if p.startswith("file://"):
        p = p[len("file://"):]
    parts = [s for s in p.split("/") if s not in ("", ".")]
    if project in parts:
        last = len(parts) - 1 - parts[::-1].index(project)   # last occurrence
        parts = parts[last + 1:]
    return "/".join(parts)


def fingerprint(f: Finding) -> str:
    code = " ".join(f.code.split())          # collapse whitespace; the line number is NOT used
    text = f"{f.tool}|{f.rule_id}|{f.path}|{code}"
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------- Semgrep (SARIF) ----------

_LEVEL_TO_SEVERITY = {"error": "high", "warning": "medium", "note": "low", "none": "info"}


def _score_to_severity(value):
    """security-severity as a number or numeric string (0 < n <= 10), else None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        try:
            value = float(value)
        except ValueError:
            return None
    if not isinstance(value, (int, float)) or not 0 < value <= 10:
        return None
    if value >= 9.0:
        return "critical"
    if value >= 7.0:
        return "high"
    if value >= 4.0:
        return "medium"
    return "low"


def _cwe_from_tags(tags):
    for tag in tags or []:
        if isinstance(tag, str):
            m = re.match(r"CWE-([0-9]+)", tag)
            if m:
                return int(m.group(1))
    return None


def load_semgrep_sarif(path, project: str) -> list[Finding]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    findings = []
    for run in data.get("runs") or []:
        rules = {r.get("id"): r for r in (((run.get("tool") or {}).get("driver") or {}).get("rules") or [])}
        for res in run.get("results") or []:
            rule = rules.get(res.get("ruleId")) or {}
            props = rule.get("properties") or {}
            severity = _score_to_severity(props.get("security-severity"))
            if severity is None:
                level = res.get("level") or (rule.get("defaultConfiguration") or {}).get("level") or "warning"
                severity = _LEVEL_TO_SEVERITY.get(str(level).lower(), "medium")
            loc = ((res.get("locations") or [{}])[0].get("physicalLocation")) or {}
            region = loc.get("region") or {}
            uri = (loc.get("artifactLocation") or {}).get("uri") or ""
            snippet = ((region.get("snippet") or {}).get("text") or "").splitlines()
            findings.append(Finding(
                tool="semgrep",
                rule_id=res.get("ruleId") or "",
                path=normalize_path(uri, project),
                line=int(region.get("startLine") or 0),
                severity=severity,
                cwe=_cwe_from_tags(props.get("tags")),
                message=(res.get("message") or {}).get("text") or "",
                code=snippet[0] if snippet else "",
            ))
    return findings


# ---------- Bandit (JSON) ----------

_BANDIT_SEVERITY = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def _as_int(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isascii() and value.isdigit():
        return int(value)
    return None


def _bandit_code_line(code, line_number):
    """Bandit's code is several lines like '10 text'; pick the one numbered line_number."""
    for raw in (code or "").split("\n"):
        number, _, text = raw.partition(" ")
        if number.isascii() and number.isdigit() and int(number) == line_number:
            return text
    return ""


def load_bandit(path, project: str) -> list[Finding]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    findings = []
    for r in data.get("results") or []:
        severity = _BANDIT_SEVERITY.get(r.get("issue_severity"), "info")
        if r.get("issue_confidence") == "LOW":          # one step lower
            severity = SEVERITIES[max(SEVERITIES.index(severity) - 1, 0)]
        line = r.get("line_number")
        findings.append(Finding(
            tool="bandit",
            rule_id=r.get("test_id") or "",
            path=normalize_path(r.get("filename") or "", project),
            line=line,
            severity=severity,
            cwe=_as_int((r.get("issue_cwe") or {}).get("id")),
            message=r.get("issue_text") or "",
            code=_bandit_code_line(r.get("code"), line),
        ))
    return findings


# ---------- grouping ----------

def issue_key(f: Finding, equivalences: dict[str, str]) -> str:
    tool_rule = f"{f.tool}:{f.rule_id}"
    if equivalences and tool_rule in equivalences:
        return equivalences[tool_rule]
    if f.cwe is not None:
        return f"CWE-{f.cwe}"
    return tool_rule


def dedupe(findings: list[Finding], equivalences: dict[str, str] | None = None) -> list[Group]:
    equivalences = equivalences or {}
    buckets: dict[tuple, list[Finding]] = {}
    for f in findings:
        buckets.setdefault((f.path, f.line, issue_key(f, equivalences)), []).append(f)
    groups = []
    for (path, line, key), members in buckets.items():
        members.sort(key=lambda m: (m.tool, m.rule_id, fingerprint(m), m.message))
        severity = max((m.severity for m in members), key=SEVERITIES.index)
        groups.append(Group(key=key, path=path, line=line, severity=severity, findings=members))
    groups.sort(key=lambda g: (-SEVERITIES.index(g.severity), g.path, g.line, g.key))
    return groups


# ---------- suppressions, baseline, gate ----------

_FP_RE = re.compile(r"[0-9a-f]{64}")


def _parse_suppression(entry):
    if not isinstance(entry, dict):
        return None
    fp, reason, by, expires = (entry.get(k) for k in ("fingerprint", "reason", "by", "expires"))
    if not (isinstance(fp, str) and _FP_RE.fullmatch(fp)):
        return None
    if not (isinstance(reason, str) and len(reason.strip()) >= 10):
        return None
    if not (isinstance(by, str) and by.strip()):
        return None
    if isinstance(expires, str):
        try:
            day = date.fromisoformat(expires)
        except ValueError:
            return None
    elif type(expires) is date:
        day = expires
    else:
        return None
    return Suppression(fingerprint=fp, reason=reason, expires=day, by=by)


def load_suppressions(entries: list[dict]) -> tuple[list[Suppression], list[dict]]:
    valid, invalid = [], []
    for entry in entries or []:
        s = _parse_suppression(entry)
        if s is None:
            invalid.append(entry)
        else:
            valid.append(s)
    return valid, invalid


def apply_suppressions(groups, suppressions, today: date):
    live = {s.fingerprint for s in suppressions if s.expires >= today}   # expires today still counts
    active, suppressed = [], []
    for g in groups:
        (suppressed if any(fp in live for fp in g.fingerprints) else active).append(g)
    return active, suppressed


def diff_baseline(groups, baseline):
    baseline = set(baseline)
    new, existing, seen = [], [], set()
    for g in groups:
        fps = g.fingerprints
        seen.update(fps)
        (existing if any(fp in baseline for fp in fps) else new).append(g)
    return new, existing, sorted(baseline - seen)


def gate(new_active: list[Group], fail_on: str) -> bool:
    limit = SEVERITIES.index(fail_on)
    return not any(SEVERITIES.index(g.severity) >= limit for g in new_active)