#!/usr/bin/env python3
"""Turn raw TruffleHog JSON lines into a redacted, allowlist-filtered report.

Usage: process_findings.py RAW_JSONL ALLOWLIST_YAML OUT_DIR [--show-secret none|redacted]

The `Raw`/`RawV2` fields are never written out; only detector name, file, line and
commit are kept. With `--show-secret redacted` TruffleHog's partial `Redacted` hint
(e.g. the AWS key ID, never the secret part) is also kept and shown as a Hint column. Writes to OUT_DIR:
  findings.json    - redacted findings that survived the allowlist
  suppressed.json  - redacted findings hidden by an allowlist entry (with reason / approver)
  comment.md       - sticky PR comment body (marker: <!-- trufflehog-report -->)
and appends `count=<n>` and `suppressed=<n>` to $GITHUB_OUTPUT when set.
"""
import argparse
import datetime
import json
import os
import re
import sys

import yaml

MARKER = "<!-- trufflehog-report -->"
MAX_EXPIRY_DAYS = 180
REQUIRED = ("reason", "expires", "approved-by")


def load_allowlist(path, today):
    with open(path) as fh:
        entries = (yaml.safe_load(fh) or {}).get("allowlist") or []
    active = []
    for i, entry in enumerate(entries):
        missing = [k for k in REQUIRED if not entry.get(k)]
        if missing or not (entry.get("path") or entry.get("detector")):
            sys.exit(f"allowlist entry #{i + 1} invalid: needs {REQUIRED} and path or detector")
        if str(entry["expires"]).strip().lower() != "never":
            expires = datetime.date.fromisoformat(str(entry["expires"]))
            if (expires - today).days > MAX_EXPIRY_DAYS:
                sys.exit(f"allowlist entry #{i + 1}: expires more than {MAX_EXPIRY_DAYS} days out (use a nearer date or `never`)")
            if expires < today:
                print(f"::warning::allowlist entry #{i + 1} expired on {expires}; no longer applied")
                continue
        active.append(entry)
    return active


def match_entry(finding, entries):
    for e in entries:
        if e.get("detector") and e["detector"] != finding["detector"]:
            continue
        if e.get("path") and not re.search(e["path"], finding["file"]):
            continue
        return e
    return None


def parse(raw_path, show_hint=False):
    findings = []
    with open(raw_path) as fh:
        for line in fh:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "DetectorName" not in obj:
                continue
            git = (obj.get("SourceMetadata") or {}).get("Data", {}).get("Git", {})
            finding = {
                "detector": obj["DetectorName"],
                "verified": bool(obj.get("Verified")),
                "file": git.get("file", "?"),
                "line": git.get("line", 0),
                "commit": git.get("commit", "?"),
            }
            if show_hint:
                finding["hint"] = str(obj.get("Redacted") or "")
            findings.append(finding)
    # de-duplicate (same secret can surface in several chunks)
    unique = [dict(t) for t in {tuple(sorted(f.items())) for f in findings}]
    unique.sort(key=lambda f: (f["file"], f["line"], f["detector"]))
    return unique


def cell(value, limit=120):
    """Make allowlist free text safe for a markdown table cell."""
    text = " ".join(str(value).split())[:limit]
    return text.replace("|", "\\|").replace("<", "&lt;").replace("`", "'")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("raw_path")
    ap.add_argument("allowlist_path")
    ap.add_argument("out_dir")
    ap.add_argument("--show-secret", choices=("none", "redacted"), default="none")
    args = ap.parse_args()
    raw_path, allowlist_path, out_dir = args.raw_path, args.allowlist_path, args.out_dir
    show_hint = args.show_secret == "redacted"
    entries = load_allowlist(allowlist_path, datetime.date.today())

    findings, suppressed = [], []
    for f in parse(raw_path, show_hint):
        entry = match_entry(f, entries)
        if entry:
            suppressed.append({**f, "reason": str(entry["reason"]),
                               "approved_by": str(entry["approved-by"]),
                               "expires": str(entry["expires"])})
        else:
            findings.append(f)

    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "findings.json"), "w") as fh:
        json.dump(findings, fh, indent=2)
    with open(os.path.join(out_dir, "suppressed.json"), "w") as fh:
        json.dump(suppressed, fh, indent=2)

    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    lines = [MARKER]
    if findings:
        verified = sum(f["verified"] for f in findings)
        lines += [
            f"### TruffleHog — {len(findings)} secret(s) found ({verified} verified)",
            "",
            "Verified credentials are **live**. Rotate them, then remove them from the branch "
            "(rotation matters more than rewriting history).",
            "",
            "| Detector | Status | File | Line | Commit |" + (" Hint |" if show_hint else ""),
            "|---|---|---|---|---|" + ("---|" if show_hint else ""),
        ]
        for f in findings:
            sha = f["commit"][:10]
            status = "verified" if f["verified"] else "unverified"
            hint = f" `{cell(f['hint'], 40)}` |" if show_hint else ""
            lines.append(f"| {f['detector']} | {status} | `{f['file']}` | {f['line']} | "
                         f"[{sha}]({server}/{repo}/commit/{f['commit']}) |{hint}")
        lines += ["", "> Secret values are intentionally not shown. To accept a finding, add an entry to "
                      "`.github/trufflehog/allowlist.yaml` (reason / expires / approved-by)."]
    elif suppressed:
        lines += [f"### TruffleHog — no un-allowlisted secrets ({len(suppressed)} allowlisted)"]
    else:
        lines += ["### TruffleHog — no verified secrets found on latest push"]

    if suppressed:
        lines += [
            "",
            f"<details><summary>{len(suppressed)} finding(s) suppressed by the allowlist — reviewers: check these</summary>",
            "",
            "| Detector | File | Line | Reason | Approved by | Expires |",
            "|---|---|---|---|---|---|",
        ]
        for s in suppressed:
            lines.append(f"| {s['detector']} | `{s['file']}` | {s['line']} | {cell(s['reason'])} | "
                         f"{cell(s['approved_by'])} | {cell(s['expires'])} |")
        lines += ["", "</details>"]

    with open(os.path.join(out_dir, "comment.md"), "w") as fh:
        fh.write("\n".join(lines) + "\n")

    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as fh:
            fh.write(f"count={len(findings)}\nsuppressed={len(suppressed)}\n")
    print(f"{len(findings)} finding(s) after allowlist, {len(suppressed)} suppressed")


if __name__ == "__main__":
    main()
