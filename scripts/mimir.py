#!/usr/bin/env python3
"""
Mimir — security audit skill for Claude Code environments.

Usage:
    mimir.py --check all [--json]
    mimir.py --check settings,secrets [--json]
    mimir.py --check vercel
    mimir.py --snapshot-baseline

Read-only. All findings are reported with exact remediation commands;
nothing is changed without the user explicitly running --snapshot-baseline
(which is the only write operation, and only touches the tamper baseline).

Configuration (optional):
    Reads ~/.config/mimir/config.json or $MIMIR_CONFIG. Recognised keys:
      - scan_roots: list of dirs to walk for git repos. Default: ["~"]
      - max_walk_depth: int. Default: 6
      - env_rotation_days: int. Default: 180
      - extra_env_paths: list of explicit .env file paths to age-check
      - exempt_public_repos: list of "owner/name" to skip on visibility check
      - extra_secret_patterns: list merged with bundled patterns
      - extra_skip_dirs: list of dir names to ignore during scan
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

HOME = Path.home()
SKILL_DIR = Path(__file__).resolve().parent.parent
REF = SKILL_DIR / "reference"
BASELINES = SKILL_DIR / "baselines"
CLAUDE_DIR = HOME / ".claude"
USER_SETTINGS = CLAUDE_DIR / "settings.json"
USER_SETTINGS_LOCAL = CLAUDE_DIR / "settings.local.json"
USER_CLAUDE_MD = CLAUDE_DIR / "CLAUDE.md"
AGENTS_SKILLS = HOME / ".agents" / "skills"

DEFAULT_CONFIG_PATH = HOME / ".config" / "mimir" / "config.json"
DEFAULT_CONFIG: dict[str, Any] = {
    "scan_roots": [str(HOME)],
    "max_walk_depth": 6,
    "env_rotation_days": 180,
    "extra_env_paths": [],
    "exempt_public_repos": [],
    "extra_secret_patterns": [],
    "extra_skip_dirs": [],
    "trusted_skills": [],
}

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_CONFIG_CACHE: dict[str, Any] | None = None


def load_config() -> dict[str, Any]:
    """Load Mimir config, merging file/env overrides over defaults.

    Resolution order:
      1. $MIMIR_CONFIG file path if set
      2. ~/.config/mimir/config.json if it exists
      3. Built-in defaults
    """
    global _CONFIG_CACHE
    if _CONFIG_CACHE is not None:
        return _CONFIG_CACHE
    cfg = dict(DEFAULT_CONFIG)
    paths_to_try: list[Path] = []
    env_cfg = os.environ.get("MIMIR_CONFIG")
    if env_cfg:
        paths_to_try.append(Path(env_cfg).expanduser())
    paths_to_try.append(DEFAULT_CONFIG_PATH)
    for p in paths_to_try:
        if p.exists():
            try:
                loaded = json.loads(p.read_text())
                if isinstance(loaded, dict):
                    cfg.update(loaded)
            except (OSError, json.JSONDecodeError):
                pass
            break
    cfg["scan_roots"] = [Path(r).expanduser() for r in cfg["scan_roots"]]
    cfg["extra_env_paths"] = [Path(p).expanduser() for p in cfg["extra_env_paths"]]
    _CONFIG_CACHE = cfg
    return cfg


def _load_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return default


def _sh(cmd: list[str], cwd: Path | None = None, timeout: int = 30) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return 1, "", str(e)


def finding(check: str, severity: str, title: str, detail: str = "",
            fix_hint: str = "", auto_fixable: bool = False,
            evidence: Any = None) -> dict:
    return {
        "check": check,
        "severity": severity,
        "title": title,
        "detail": detail,
        "fix_hint": fix_hint,
        "auto_fixable": auto_fixable,
        "evidence": evidence,
    }


# ---------- check: settings ----------
def check_settings(autofix: bool = False) -> tuple[list[dict], list[dict]]:
    findings: list[dict] = []
    actions: list[dict] = []

    user_s = _load_json(USER_SETTINGS, {}) or {}
    perms = user_s.get("permissions", {}) if isinstance(user_s, dict) else {}

    if perms.get("defaultMode") == "bypassPermissions":
        findings.append(finding(
            "settings", "info",
            "bypassPermissions is active",
            "All tool calls skip the permission prompt. This is your chosen posture; "
            "documented here so Mimir can verify it's intentional on each run.",
        ))

    if user_s.get("skipDangerousModePermissionPrompt") is True:
        findings.append(finding(
            "settings", "info",
            "skipDangerousModePermissionPrompt is true",
            "The 'you're in dangerous mode' warning at session start is suppressed.",
        ))

    addl = perms.get("additionalDirectories", []) or []
    if HOME.as_posix() in addl or "/" in addl:
        findings.append(finding(
            "settings", "critical",
            "additionalDirectories grants Claude access to $HOME or /",
            "Read/Edit/Write tools can touch anything on disk.",
            "Narrow additionalDirectories to specific project roots.",
            evidence={"additionalDirectories": addl},
        ))

    allow = perms.get("allow", []) or []
    if any(p in ("Read(*)", "Edit(*)", "Write(*)") for p in allow):
        wildcards = [p for p in allow if p in ("Read(*)", "Edit(*)", "Write(*)")]
        findings.append(finding(
            "settings", "medium",
            "Wildcard Read/Edit/Write allowed",
            "Any file under additionalDirectories can be read/modified silently. "
            "Combined with bypass mode this is the persistence vector — a prompt "
            "injection can rewrite CLAUDE.md, skills, or settings.json.",
            evidence={"patterns": wildcards},
        ))

    return findings, actions


# ---------- check: secrets ----------
def check_secrets(autofix: bool = False) -> tuple[list[dict], list[dict]]:
    findings: list[dict] = []
    actions: list[dict] = []

    cfg = _load_json(REF / "secret_patterns.json", {}) or {}
    user_cfg = load_config()
    raw_patterns = list(cfg.get("patterns", [])) + list(user_cfg.get("extra_secret_patterns", []))
    patterns = [(p["name"], re.compile(p["regex"]), p["severity"]) for p in raw_patterns]
    blocklist = set(cfg.get("filename_blocklist", []))
    scan_exts = set(cfg.get("scan_extensions", []))
    skip_dirs = set(cfg.get("skip_dirs", [])) | set(user_cfg.get("extra_skip_dirs", []))
    gi_baseline = (REF / "gitignore_baseline.txt").read_text().splitlines()

    repos: list[Path] = []
    for root in user_cfg["scan_roots"]:
        repos.extend(_find_git_repos(root, max_depth=user_cfg["max_walk_depth"],
                                     extra_skip=skip_dirs))

    # 1) blocklisted filenames TRACKED in git
    for repo in repos:
        code, out, _ = _sh(["git", "ls-files"], cwd=repo, timeout=60)
        if code != 0:
            continue
        tracked = out.splitlines()
        for f in tracked:
            base = Path(f).name
            if base in blocklist:
                findings.append(finding(
                    "secrets", "critical",
                    f"Sensitive file tracked in git: {base}",
                    f"Repo: {repo}\nFile: {f}",
                    "Remove from history with `git filter-repo` or BFG, rotate any "
                    "credentials it ever held, and add to .gitignore.",
                    evidence={"repo": str(repo), "file": f},
                ))

    # 2) committed secret strings (HEAD only — fast, not full history)
    for repo in repos:
        code, out, _ = _sh(["git", "ls-files"], cwd=repo, timeout=60)
        if code != 0:
            continue
        for rel in out.splitlines():
            ext = Path(rel).suffix.lower()
            if ext and ext not in scan_exts:
                continue
            if any(part in skip_dirs for part in Path(rel).parts):
                continue
            full = repo / rel
            try:
                if full.stat().st_size > 2_000_000:
                    continue
                text = full.read_text(errors="ignore")
            except OSError:
                continue
            for name, rx, sev in patterns:
                m = rx.search(text)
                if not m:
                    continue
                snippet = m.group(0)
                if len(snippet) > 40:
                    snippet = snippet[:20] + "..." + snippet[-8:]
                if name == "Generic high-entropy hex" and any(
                    k in text.lower() for k in ("sha", "hash", "checksum", "commit",
                                                "etag", "uuid", "fingerprint")
                ):
                    continue
                findings.append(finding(
                    "secrets", sev,
                    f"{name} appears in tracked file",
                    f"Repo: {repo}\nFile: {rel}",
                    "Rotate immediately, remove from history, add filename to .gitignore.",
                    evidence={"repo": str(repo), "file": rel, "match": snippet},
                ))
                break

    # 3) gitignore baseline coverage
    for repo in repos:
        gi_path = repo / ".gitignore"
        existing = gi_path.read_text().splitlines() if gi_path.exists() else []
        existing_set = {ln.strip() for ln in existing if ln.strip() and not ln.startswith("#")}
        baseline_entries = [ln for ln in gi_baseline
                            if ln.strip() and not ln.startswith("#")]
        missing = [ln for ln in baseline_entries if ln not in existing_set]
        if not missing:
            continue
        findings.append(finding(
            "secrets", "medium",
            f"{Path(repo).name}: .gitignore missing {len(missing)} baseline entries",
            f"Repo: {repo}",
            f"Append the missing entries to {gi_path}. See evidence.missing for the list.",
            evidence={"repo": str(repo), "missing": missing[:20]},
        ))

    return findings, actions


# ---------- check: vercel ----------
def check_vercel(autofix: bool = False) -> tuple[list[dict], list[dict]]:
    findings: list[dict] = []
    if not shutil.which("vercel"):
        findings.append(finding("vercel", "info", "Vercel CLI not installed", ""))
        return findings, []

    code, out, _ = _sh(["vercel", "projects", "ls", "--json"], timeout=60)
    if code != 0:
        findings.append(finding("vercel", "info",
                                "Vercel CLI not logged in or org not selected", out[:200]))
        return findings, []

    try:
        projects = json.loads(out) if out.strip().startswith(("{", "[")) else []
    except json.JSONDecodeError:
        projects = []

    if not isinstance(projects, list):
        projects = projects.get("projects", []) if isinstance(projects, dict) else []

    cron_projects_with_sso = []
    for p in projects:
        name = p.get("name", "?")
        sso = p.get("ssoProtection")
        crons = p.get("crons") or []
        if sso and crons:
            cron_projects_with_sso.append(name)

    if cron_projects_with_sso:
        findings.append(finding(
            "vercel", "high",
            f"{len(cron_projects_with_sso)} cron project(s) have SSO protection",
            "SSO blocks Vercel Cron from hitting endpoints. Crons will silently fail.",
            "PATCH ssoProtection to null; gate crons with CRON_SECRET instead.",
            evidence={"projects": cron_projects_with_sso},
        ))

    return findings, []


# ---------- check: github ----------
def check_github(autofix: bool = False) -> tuple[list[dict], list[dict]]:
    findings: list[dict] = []
    if not shutil.which("gh"):
        findings.append(finding("github", "info", "gh CLI not installed", ""))
        return findings, []

    code, out, _ = _sh(["gh", "auth", "status"], timeout=15)
    if code != 0:
        findings.append(finding("github", "info", "gh CLI not authenticated", ""))
        return findings, []

    user_cfg = load_config()
    exempt = set(user_cfg.get("exempt_public_repos", []))
    repos: list[Path] = []
    for root in user_cfg["scan_roots"]:
        repos.extend(_find_git_repos(root, max_depth=user_cfg["max_walk_depth"]))
    public_when_should_be_private = []
    for repo in repos:
        code, out, _ = _sh(["git", "config", "--get", "remote.origin.url"], cwd=repo, timeout=10)
        if code != 0:
            continue
        url = out.strip()
        m = re.match(r"(?:git@github\.com:|https://github\.com/)([^/]+)/([^/.]+)", url)
        if not m:
            continue
        owner, name = m.group(1), m.group(2)
        code, out, _ = _sh(["gh", "repo", "view", f"{owner}/{name}",
                            "--json", "visibility,isPrivate"], timeout=15)
        if code != 0:
            continue
        try:
            info = json.loads(out)
        except json.JSONDecodeError:
            continue
        if info.get("visibility") == "PUBLIC" and f"{owner}/{name}" not in exempt:
            public_when_should_be_private.append(f"{owner}/{name}")

    if public_when_should_be_private:
        findings.append(finding(
            "github", "high",
            f"{len(public_when_should_be_private)} repo(s) under your account are PUBLIC",
            "Confirm each is intentionally public. Anything client-touching, "
            "credential-touching, or containing internal logic should be private.",
            "gh repo edit <repo> --visibility private",
            evidence={"public_repos": public_when_should_be_private},
        ))

    return findings, []


# ---------- check: supply chain ----------
def check_supply(autofix: bool = False) -> tuple[list[dict], list[dict]]:
    findings: list[dict] = []
    user_cfg = load_config()
    repos: list[Path] = []
    for root in user_cfg["scan_roots"]:
        repos.extend(_find_git_repos(root, max_depth=user_cfg["max_walk_depth"]))
    for repo in repos:
        if (repo / "package.json").exists() and (repo / "package-lock.json").exists():
            if shutil.which("npm"):
                code, out, _ = _sh(["npm", "audit", "--json"], cwd=repo, timeout=90)
                if code in (0, 1) and out.strip():
                    try:
                        rep = json.loads(out)
                        meta = rep.get("metadata", {}).get("vulnerabilities", {})
                        critical = meta.get("critical", 0)
                        high = meta.get("high", 0)
                        if critical or high:
                            findings.append(finding(
                                "supply", "high" if critical else "medium",
                                f"{Path(repo).name}: {critical} critical, {high} high npm vulns",
                                "",
                                "cd into repo and run `npm audit fix`. Manual review for major-version bumps.",
                                evidence={"repo": str(repo), "summary": meta},
                            ))
                    except json.JSONDecodeError:
                        pass
        if (repo / "package.json").exists() and not (repo / "package-lock.json").exists() \
                and not (repo / "yarn.lock").exists() and not (repo / "pnpm-lock.yaml").exists():
            findings.append(finding(
                "supply", "medium",
                f"{Path(repo).name}: no lockfile",
                "Without a lockfile, every install pulls the latest matching versions. "
                "Supply-chain attacks land instantly.",
                "Run `npm install` to generate package-lock.json and commit it.",
                evidence={"repo": str(repo)},
            ))
    return findings, []


# ---------- check: tamper ----------
def check_tamper(autofix: bool = False) -> tuple[list[dict], list[dict]]:
    findings: list[dict] = []
    actions: list[dict] = []
    snapshot = BASELINES / "claude_config_baseline.json"
    current = _build_config_fingerprint()

    if not snapshot.exists():
        findings.append(finding(
            "tamper", "info",
            "No tamper baseline yet",
            "Future runs will compare ~/.claude/CLAUDE.md, settings.json, settings.local.json, "
            "and ~/.claude/skills + ~/.agents/skills against a baseline.",
            "Run `python3 ~/.claude/skills/mimir/scripts/mimir.py --snapshot-baseline` to create one.",
        ))
        return findings, actions

    baseline = _load_json(snapshot, {}) or {}
    diffs = []
    for k, v in current.items():
        if baseline.get(k) != v:
            diffs.append({"key": k, "old": baseline.get(k), "new": v})
    if diffs:
        findings.append(finding(
            "tamper", "high",
            f"{len(diffs)} Claude config file(s) changed since baseline",
            "These could be legitimate edits OR persistence from a prompt injection. "
            "Review each diff.",
            "Run `git diff` on the files if they're in repos, otherwise inspect manually. "
            "Re-baseline with `mimir.py --snapshot-baseline` after confirming.",
            evidence={"changed": [d["key"] for d in diffs]},
        ))
    return findings, actions


# ---------- check: rotation ----------
def check_rotation(autofix: bool = False) -> tuple[list[dict], list[dict]]:
    findings: list[dict] = []
    user_cfg = load_config()
    threshold = int(user_cfg.get("env_rotation_days", 180))
    explicit = list(user_cfg.get("extra_env_paths", []))

    discovered: set[Path] = set()
    for root in user_cfg["scan_roots"]:
        for repo in _find_git_repos(root, max_depth=user_cfg["max_walk_depth"]):
            for name in (".env", ".env.local", ".env.production"):
                p = repo / name
                if p.exists():
                    discovered.add(p)

    all_paths = sorted(set(explicit) | discovered)
    now = _dt.datetime.now().timestamp()
    for p in all_paths:
        if not p.exists():
            continue
        age_days = (now - p.stat().st_mtime) / 86400
        if age_days > threshold:
            findings.append(finding(
                "rotation", "medium",
                f".env last touched {int(age_days)} days ago: {p.name}",
                f"Path: {p}",
                "Rotate long-lived tokens and update every consumer in lockstep "
                "(deploy platform env vars, CI secrets, MCP server configs).",
                evidence={"path": str(p), "age_days": int(age_days)},
            ))
    return findings, []


# ---------- helpers ----------
def _find_git_repos(root: Path, max_depth: int = 6,
                    extra_skip: set[str] | None = None) -> list[Path]:
    repos: list[Path] = []
    if not root.exists():
        return repos
    skip = {"node_modules", ".next", ".vercel", "dist", "build",
            "__pycache__", ".venv", "venv", ".turbo", ".cache",
            "Library", "Applications", ".Trash", ".npm", ".nvm",
            ".pyenv", ".rbenv", ".local", ".cargo", ".rustup"}
    if extra_skip:
        skip |= extra_skip
    for dirpath, dirnames, _filenames in os.walk(root):
        depth = Path(dirpath).relative_to(root).parts
        if len(depth) > max_depth:
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if d not in skip and not d.startswith(".")
                       or d == ".git"]
        if ".git" in dirnames:
            repos.append(Path(dirpath))
            dirnames[:] = [d for d in dirnames if d != ".git"]
    return repos


def _build_config_fingerprint() -> dict[str, str]:
    fp: dict[str, str] = {}
    for p in [USER_CLAUDE_MD, USER_SETTINGS, USER_SETTINGS_LOCAL]:
        if p.exists():
            fp[str(p)] = hashlib.sha256(p.read_bytes()).hexdigest()
    for base in [CLAUDE_DIR / "skills", AGENTS_SKILLS]:
        if not base.exists():
            continue
        for sk in sorted(base.iterdir()):
            md = sk / "SKILL.md" if sk.is_dir() else sk
            if md.exists() and md.is_file():
                fp[str(md)] = hashlib.sha256(md.read_bytes()).hexdigest()
    return fp


def snapshot_baseline() -> None:
    BASELINES.mkdir(parents=True, exist_ok=True)
    snapshot = BASELINES / "claude_config_baseline.json"
    fp = _build_config_fingerprint()
    snapshot.write_text(json.dumps(fp, indent=2))
    print(f"Wrote baseline: {snapshot} ({len(fp)} files)")


def check_skills(autofix: bool = False) -> tuple[list[dict], list[dict]]:
    """Inspect installed skills for risky content and unverified provenance."""
    findings: list[dict] = []
    risky_patterns_cfg = _load_json(REF / "skill_risk_patterns.json", {}) or {}
    user_cfg = load_config()
    risky_patterns = [(p["name"], re.compile(p["regex"], re.IGNORECASE), p["severity"])
                      for p in risky_patterns_cfg.get("patterns", [])]
    trusted_remotes = set(risky_patterns_cfg.get("trusted_remotes", []))
    trusted_skills = set(risky_patterns_cfg.get("trusted_skills", []))
    trusted_skills |= set(user_cfg.get("trusted_skills", []))

    skill_roots = [CLAUDE_DIR / "skills", AGENTS_SKILLS]
    seen_targets: set[Path] = set()
    skills: list[tuple[str, Path]] = []
    for root in skill_roots:
        if not root.exists():
            continue
        for entry in sorted(root.iterdir()):
            target = entry.resolve() if entry.is_symlink() else entry
            if target in seen_targets:
                continue
            seen_targets.add(target)
            skill_md = target / "SKILL.md" if target.is_dir() else target
            if skill_md.exists() and skill_md.is_file():
                skills.append((entry.name, target))

    for name, path in skills:
        if name in trusted_skills:
            continue
        sm = path / "SKILL.md"
        try:
            content = sm.read_text(errors="ignore")
        except OSError:
            continue
        for pat_name, rx, sev in risky_patterns:
            m = rx.search(content)
            if not m:
                continue
            snippet = m.group(0)
            if len(snippet) > 80:
                snippet = snippet[:60] + "..."
            findings.append(finding(
                "skills", sev,
                f"Skill '{name}' contains risky pattern: {pat_name}",
                f"Path: {sm}\nMatch: {snippet}",
                "Read the full SKILL.md and any scripts/. If unfamiliar, uninstall by "
                "removing the directory or symlink.",
                evidence={"skill": name, "path": str(sm), "pattern": pat_name},
            ))

        scripts_dir = path / "scripts"
        if scripts_dir.exists() and scripts_dir.is_dir():
            for sp in scripts_dir.rglob("*"):
                if not sp.is_file():
                    continue
                if sp.suffix in (".py", ".sh", ".js", ".mjs", ".ts"):
                    try:
                        body = sp.read_text(errors="ignore")
                    except OSError:
                        continue
                    for pat_name, rx, sev in risky_patterns:
                        m = rx.search(body)
                        if m:
                            snippet = m.group(0)
                            if len(snippet) > 80:
                                snippet = snippet[:60] + "..."
                            findings.append(finding(
                                "skills", sev,
                                f"Skill '{name}' script has risky pattern: {pat_name}",
                                f"Script: {sp}\nMatch: {snippet}",
                                "Inspect the script. Risky scripts in skills run as you "
                                "whenever the skill executes.",
                                evidence={"skill": name, "script": str(sp), "pattern": pat_name},
                            ))
                            break

        git_dir = path / ".git"
        if git_dir.exists():
            code, out, _ = _sh(["git", "config", "--get", "remote.origin.url"],
                               cwd=path, timeout=5)
            remote = out.strip() if code == 0 else ""
            if not remote:
                findings.append(finding(
                    "skills", "low",
                    f"Skill '{name}' is a git repo with no origin remote",
                    f"Path: {path}",
                    "Confirm where this skill came from. Local-only skills can be fine, "
                    "but unknown provenance is a yellow flag.",
                    evidence={"skill": name},
                ))
            else:
                trusted = any(t in remote for t in trusted_remotes)
                if not trusted:
                    findings.append(finding(
                        "skills", "low",
                        f"Skill '{name}' is from an untrusted remote",
                        f"Remote: {remote}",
                        "If you didn't personally vet this remote, treat skill output as "
                        "potentially adversarial.",
                        evidence={"skill": name, "remote": remote},
                    ))
    return findings, []


CHECKS = {
    "settings": check_settings,
    "secrets": check_secrets,
    "vercel": check_vercel,
    "github": check_github,
    "supply": check_supply,
    "tamper": check_tamper,
    "rotation": check_rotation,
    "skills": check_skills,
}


def main() -> int:
    ap = argparse.ArgumentParser(description="Mimir security audit (read-only)")
    ap.add_argument("--check", default="all",
                    help="comma-separated: " + ",".join(CHECKS) + ",all")
    ap.add_argument("--json", action="store_true",
                    help="Emit machine-readable JSON instead of human text")
    ap.add_argument("--snapshot-baseline", action="store_true",
                    help="Write a fresh tamper-detection baseline and exit (the only write operation)")
    args = ap.parse_args()

    if args.snapshot_baseline:
        snapshot_baseline()
        return 0

    requested = (list(CHECKS.keys()) if args.check == "all"
                 else [c.strip() for c in args.check.split(",") if c.strip() in CHECKS])

    all_findings: list[dict] = []
    for c in requested:
        f, _ = CHECKS[c](autofix=False)
        all_findings.extend(f)

    all_findings.sort(key=lambda x: SEV_ORDER.get(x["severity"], 9))

    if args.json:
        print(json.dumps({
            "ran_at": _dt.datetime.now().isoformat(timespec="seconds"),
            "checks": requested,
            "findings": all_findings,
        }, indent=2))
        return 0

    # Human report
    print(f"Mimir audit — {_dt.datetime.now():%Y-%m-%d %H:%M}")
    print(f"Checks: {', '.join(requested)}\n")
    if not all_findings:
        print("No findings. Mimir sees nothing amiss.")
        return 0
    by_sev: dict[str, list[dict]] = {}
    for f in all_findings:
        by_sev.setdefault(f["severity"], []).append(f)
    for sev in ("critical", "high", "medium", "low", "info"):
        if sev not in by_sev:
            continue
        print(f"== {sev.upper()} ({len(by_sev[sev])}) ==")
        for f in by_sev[sev]:
            print(f"  [{f['check']}] {f['title']}")
            if f["detail"]:
                for line in f["detail"].splitlines():
                    print(f"      {line}")
            if f["fix_hint"]:
                print(f"      Fix: {f['fix_hint']}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
