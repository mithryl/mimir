---
name: mimir
description: Use when the user asks to summon Mimir, run a security audit, run a security check, scan for vulnerabilities, asks "am I exposed", "what's my risk", "is this safe", "audit my setup", or types /mimir. Performs a full machine + account security audit covering settings posture (bypass mode, hooks, wildcard Read/Edit/Write), secret exposure across git repos under configured scan roots (committed tokens, .env tracking, gitignore gaps), Vercel posture (SSO on cron projects), GitHub posture (public-by-mistake repos), supply chain (npm audit, missing lockfiles), tamper detection on Claude config and skills, installed-skill content inspection (risky patterns, provenance), and credential rotation freshness. Auto-fixes safe items (gitignore appends, baseline snapshots); reports risky items (committed secrets, public repos, vulnerable deps, risky skill content) for the user's approval.
---

# Mimir

Norse god of wisdom whose severed head Odin keeps for counsel. Sees what's lurking in the configuration.

## When to Use

Triggers:
- `/mimir` (preferred)
- "summon mimir", "run mimir", "ask mimir"
- "run a security audit", "audit my setup", "security check"
- "am I exposed", "what's my risk", "what are my vulnerabilities", "is this safe"
- After installing a new MCP server or skill, after rotating credentials, after a session in which a stranger's content was processed (PDFs, transcripts, scraped pages) — Mimir confirms nothing landed it shouldn't have

Do NOT auto-summon Mimir mid-task. Wait for an explicit trigger. Mimir is a deliberate, focused operation, not background noise.

## What Mimir Audits

| Check | What it looks for | Auto-fix? |
|---|---|---|
| `settings` | bypassPermissions state, dangerous additionalDirectories scope, wildcard Read/Edit/Write | No — bypass mode is the user's chosen posture; deny rules are not auto-managed |
| `secrets` | Committed .env / credentials files, plaintext API tokens (Anthropic, OpenAI, GitHub, Vercel, HubSpot, Notion, AWS, Stripe, Slack, Twilio, SendGrid, etc.) in tracked files, gitignore baseline coverage | Appends missing gitignore entries |
| `vercel` | Cron projects with ssoProtection (silently breaks crons) | No — reports for manual PATCH |
| `github` | Repos under the user's account that are accidentally public | No — reports for manual review |
| `supply` | npm audit critical/high vulns, missing lockfiles | No — reports for manual `npm audit fix` |
| `tamper` | Diff of `~/.claude/CLAUDE.md`, settings files, and every SKILL.md against the last-confirmed baseline. Flags unexpected changes that could be prompt-injection persistence | Writes initial baseline; subsequent baselines require user confirmation |
| `skills` | Inspects every installed skill's SKILL.md and scripts for risky patterns (pipe-to-shell, eval on user input, .env reads, settings tampering, hook installation, reverse-shell shapes) and checks git provenance against a trusted-remote allowlist | No — reports for manual review |
| `rotation` | `.env` files older than N days (default 180) | No — reports for manual rotation |

## How to Run It

The audit logic lives in `scripts/mimir.py`. Default invocation:

```bash
python3 ~/.claude/skills/mimir/scripts/mimir.py --check all --autofix-safe --json
```

Flags:
- `--check` — comma-separated list (`settings,secrets,vercel,github,supply,tamper,skills,rotation`) or `all` (default)
- `--autofix-safe` — apply non-destructive fixes (gitignore appends, initial baseline). Without this, run is read-only.
- `--json` — machine-readable output (what you should request when invoking Mimir from inside Claude Code)
- `--snapshot-baseline` — overwrite tamper-detection baseline (use AFTER the user confirms a config change was intentional)

## Configuration

Mimir reads `~/.config/mimir/config.json` if it exists, falling back to built-in defaults. Recognised keys:

```json
{
  "scan_roots": ["~/projects", "~/work"],
  "max_walk_depth": 6,
  "env_rotation_days": 180,
  "extra_env_paths": ["/path/to/specific/.env"],
  "exempt_public_repos": ["owner/repo-name"],
  "extra_secret_patterns": [
    {"name": "Internal token", "regex": "INT-[A-Z0-9]{32}", "severity": "critical"}
  ],
  "extra_skip_dirs": ["vendor", "third_party"]
}
```

If no config file exists, Mimir walks `$HOME` looking for git repos. Override the file location via `$MIMIR_CONFIG`.

## Process

### Routing the invocation

First, decide which mode the user invoked Mimir in:

| User said... | Mode |
|---|---|
| "summon mimir and do a full audit" / "/mimir full" / "/mimir audit" / "/mimir all" / any phrasing that explicitly asks for the audit to run | **Audit mode** — skip onboarding, just run |
| "summon mimir" / "/mimir" alone, with no qualifier | **Maybe onboard** — if `~/.config/mimir/config.json` does not exist, run onboarding first. Otherwise treat as Audit mode. |
| "/mimir onboard" / "configure mimir" / "set up mimir" | **Onboarding mode** — always run onboarding, even if config exists |

### Onboarding mode

Used the first time a user summons Mimir (no `~/.config/mimir/config.json`) or on explicit request. Goal: build a config in 4 questions or fewer, then offer to run the audit.

1. **Announce.** "First time summoning Mimir — quick 4-question onboarding, then we audit."
2. **Ask, using AskUserQuestion (one batch):**
   - Which directories should Mimir scan for git repos? (default: `$HOME` with depth 6)
   - Any repos that are intentionally public and should be exempted from the GitHub check? (default: none)
   - Rotation threshold for `.env` files, in days? (default: 180)
   - Any extra directories to skip during scans (e.g. `vendor`, `third_party`)? (default: none)
3. **Write `~/.config/mimir/config.json`** with the answers. Create the parent dir if needed.
4. **Run the audit** in Audit mode using the new config.

If the user wants to skip onboarding ("just run the audit"), proceed to Audit mode without writing the config — Mimir's defaults are sane.

### Audit mode

1. **Announce.** One sentence: "Summoning Mimir — running full audit with safe auto-fixes."
2. **Run the audit** with `--autofix-safe --json`. Capture the JSON.
3. **Parse findings**, group by severity (critical → high → medium → low → info), and present a prioritized table. Format:
   - Severity badge
   - Short title
   - One-line detail
   - Specific remediation (file path, exact command, etc.)
4. **Surface the auto-fixes that were applied** in a separate, smaller section: "Mimir fixed N things automatically — here they are."
5. **Wait for the user's call on the risky items.** Do not auto-remediate critical/high findings. For each one, offer the specific next step and let the user choose.
6. **Re-baseline only on request.** If the user confirms that flagged tamper-changes were intentional, run `--snapshot-baseline` to update.

## Output Shape

```
Mimir's report — 2026-05-26 09:51
Auto-fixes applied: 2
  - appended 4 entries to repo-x/.gitignore
  - wrote initial tamper baseline

CRITICAL (2)
  [secrets] HubSpot access token in tracked file
    Repo: ~/projects/foo
    File: src/lib/hubspot.ts
    Fix: rotate the token immediately, remove from history with `git filter-repo`,
         add the literal value to .gitignore patterns if applicable

HIGH (3)
  [vercel] 2 cron project(s) have SSO protection enabled
    Projects: daily-calendar-digest, deposit-log
    Fix: PATCH ssoProtection to null on each; gate with CRON_SECRET instead.

  [skills] Skill 'foo' contains risky pattern: Pipe-to-shell install
    Path: ~/.claude/skills/foo/SKILL.md
    Fix: read the full SKILL.md and scripts/. Uninstall if unfamiliar.
  ...

INFO (2)
  [settings] bypassPermissions is active — confirmed intentional
  [settings] skipDangerousModePermissionPrompt is true — confirmed intentional
```

## Hard Rules

1. **Never auto-rotate credentials.** Rotation breaks every consumer of that token; only the user can sequence that.
2. **Never auto-rewrite git history.** `git filter-repo` is destructive and forces every collaborator to re-clone. Report-only.
3. **Never auto-PATCH Vercel projects.** Mistaken SSO toggles can expose internal dashboards.
4. **Never auto-change repo visibility.** Public/private is a deliberate business decision.
5. **Never auto-apply `npm audit fix`.** Major-version bumps can break the build.
6. **Never auto-uninstall a skill.** A risky-pattern flag is a prompt for the user to look, not a verdict.
7. **Always re-read the baseline before re-snapshotting.** A baseline written during a compromised session locks the compromise in.
8. **Use the JSON output when invoking from a Claude session.** Human output is for terminal use.

## Adding a Check

1. Add a `check_<name>()` function to `scripts/mimir.py` returning `(findings, actions)`.
2. Register it in the `CHECKS` dict.
3. Add a row to the "What Mimir Audits" table above.
4. Add reference data (regex patterns, etc.) under `reference/`.

## Adding a Secret Pattern

Edit `reference/secret_patterns.json` (bundled defaults) or add to `extra_secret_patterns` in `~/.config/mimir/config.json` (user-specific). Each entry needs `name`, `regex`, and `severity` (`critical`, `high`, `medium`, `low`). Test the regex against a real-looking sample value first.

## Adding a Trusted Skill Remote

Edit `reference/skill_risk_patterns.json` and append the URL substring to `trusted_remotes`. Anything matching that substring on `git config --get remote.origin.url` is considered vetted.
