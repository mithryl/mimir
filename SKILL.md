---
name: mimir
description: Use when the user asks to summon Mimir, run a security audit, run a security check, scan for vulnerabilities, asks "am I exposed", "what's my risk", "is this safe", "audit my setup", or types /mimir. Performs a read-only machine + account security audit covering settings posture (bypass mode, hooks, wildcard Read/Edit/Write), secret exposure across git repos under configured scan roots (committed tokens, .env tracking, gitignore gaps), Vercel posture (SSO on cron projects), GitHub posture (public-by-mistake repos), supply chain (npm audit, missing lockfiles, install-cooldown policy against self-propagating package worms), tamper detection on Claude config and skills, installed-skill content inspection (risky patterns, provenance), and credential rotation freshness. Reports every finding with a specific remediation; never changes anything on disk without the user's explicit say-so. Also runs project-scoped app-code audits — triggers "summon mimir to audit security", "summon mimir to audit performance", "summon mimir to audit the UI", or /mimir security|performance|ui — that review a single project's source against security, performance, and UI/UX checklists and report findings by severity. App audits are review-and-report by default; fixes are applied only on explicit opt-in, on a dedicated mimir/* branch with one commit per fix, never on main and never without the user's say-so.
---

# Mimir

Norse god of wisdom whose severed head Odin keeps for counsel. Sees what's lurking in the configuration.

## When to Use

Triggers:
- `/mimir` (preferred)
- "summon mimir", "run mimir", "ask mimir"
- "run a security audit", "audit my setup", "security check"
- "am I exposed", "what's my risk", "what are my vulnerabilities", "is this safe"
- App-code audit scoped to one project: "summon mimir to audit security", "summon mimir to audit performance", "summon mimir to audit the UI", or `/mimir security` / `/mimir performance` / `/mimir ui`
- After installing a new MCP server or skill, after rotating credentials, after a session in which a stranger's content was processed (PDFs, transcripts, scraped pages) — Mimir confirms nothing landed it shouldn't have

Do NOT auto-summon Mimir mid-task. Wait for an explicit trigger. Mimir is a deliberate, focused operation, not background noise.

## What Mimir Audits

Mimir is **read-only**. Every check reports findings with a specific remediation; nothing is written to disk except via the explicit `--snapshot-baseline` command (which only touches the tamper baseline file).

The table below is the **environment audit** (machine + accounts), run by `/mimir`. Mimir also runs **app-code audits** scoped to a single project — security, performance, and UI/UX — driven by the checklists in `reference/app_checks/`. Those are a separate surface; see "App audit mode" under Process.

| Check | What it looks for |
|---|---|
| `settings` | bypassPermissions state, dangerous additionalDirectories scope, wildcard Read/Edit/Write |
| `secrets` | Committed .env / credentials files, plaintext API tokens (Anthropic, OpenAI, GitHub, Vercel, HubSpot, Notion, AWS, Stripe, Slack, Twilio, SendGrid, etc.) in tracked files, gitignore baseline coverage |
| `vercel` | Cron projects with ssoProtection (silently breaks crons) |
| `github` | Repos under the user's account that are accidentally public |
| `supply` | npm audit critical/high vulns, missing lockfiles |
| `cooldown` | Missing package-install cooldown policy (no `minimumReleaseAge` window) — defense against self-propagating npm/PyPI worms that republish stolen-token payloads minutes after a version goes live |
| `tamper` | Diff of `~/.claude/CLAUDE.md`, settings files, and every SKILL.md against the last-confirmed baseline. Flags unexpected changes that could be prompt-injection persistence |
| `skills` | Inspects every installed skill's SKILL.md and scripts for risky patterns (pipe-to-shell, eval on user input, .env reads, settings tampering, hook installation, reverse-shell shapes) and checks git provenance against a trusted-remote allowlist |
| `rotation` | `.env` files older than N days (default 180) |

## How to Run It

The audit logic lives in `scripts/mimir.py`. Default invocation:

```bash
python3 ~/.claude/skills/mimir/scripts/mimir.py --check all --json
```

Flags:
- `--check` — comma-separated list (`settings,secrets,vercel,github,supply,cooldown,tamper,skills,rotation`) or `all` (default)
- `--path DIR` — scope this run to one or more specific folders (repeatable), overriding `scan_roots` from config. Use when the user points Mimir at a single project instead of the whole machine. Exits non-zero if a path doesn't exist. Does not affect machine-wide checks (`settings`, `tamper`, `skills`) which always inspect Claude config.
- `--json` — machine-readable output (what you should request when invoking Mimir from inside Claude Code)
- `--snapshot-baseline` — write the tamper-detection baseline. The only write operation Mimir performs; only run after the user explicitly confirms.

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
| "summon mimir to audit security / performance / the UI" / "/mimir security" / "/mimir performance" / "/mimir ui" | **App audit mode** — review one project's source against the matching checklist (see below) |

**Disambiguation (environment vs app).** Bare "run a security audit" / "am I exposed" / "audit my setup" means the **environment** audit (machine + accounts). A request that points at code, an app, a project, the UI, or performance means the **app audit**. If a security request is genuinely ambiguous between machine posture and this project's code, ask one clarifying question before running.

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

1. **Announce.** One sentence: "Summoning Mimir — running read-only audit."
2. **Run the audit** with `--json`. Capture the JSON. Do not pass any flag that would write to disk. If the user pointed Mimir at a specific folder ("scan this repo", "audit ~/projects/foo"), pass `--path <folder>` to scope the repo-walking checks to just that folder instead of the whole machine.
3. **Parse findings**, group by severity (critical → high → medium → low → info), and present a prioritized table. Format:
   - Severity badge
   - Short title
   - One-line detail
   - Specific remediation (file path, exact command, etc.)
4. **Wait for the user's call on every finding.** Mimir never changes anything on disk. For each finding, present the remediation and let the user choose whether to apply it. Group small batches of similar items (e.g. "the same missing gitignore entry across 10 repos") so they can be approved or skipped as a set.
5. **Re-baseline only on explicit request.** If the user confirms that flagged tamper-changes were intentional, run `--snapshot-baseline` to update.

### App audit mode

Triggered by "summon mimir to audit security / performance / the UI" (or `/mimir security|performance|ui`). This audits **one project's source code**, not the machine. It is read-only review-and-report by default; nothing in the project is edited without an explicit opt-in.

1. **Resolve the target project.** Use the current working directory if it is inside a git repo, or the path the user named ("audit ~/Developer/.../drift"). Confirm it in one line. If it is not a git repo, say so and ask before proceeding — the opt-in fix step needs a clean branch.
2. **Announce.** One sentence: "Summoning Mimir — read-only <security|performance|UI> review of <project>."
3. **Load the checklist** for the mode from `reference/app_checks/<security|performance|ui>.md`. Each file holds 100 checks, each with a default severity and inline dedup notes.
4. **Review, do not edit.** Work through the checklist against the project's source. Record a finding only where the issue is genuinely present: severity (adjust the per-class default to the actual instance), short title, `file:line`, one-line detail, and the specific remediation from the check text. Mark inapplicable checks N/A with a one-line reason. Honor the dedup notes — do not re-report what another mode or the environment audit already owns.
5. **Stream findings to a report file OUTSIDE the project**, so the target repo stays untouched and a context reset never loses progress: `~/.config/mimir/reports/<project>-<mode>-<YYYY-MM-DD>.md` (create the dir if needed). This is the only write the app audit makes, and it never touches the audited repo. Because a 100-check pass will compact context, the report file plus the checklist are the source of truth after any reset — resume from the first unrecorded check.
6. **Present** the prioritized severity table (same Output Shape as the environment audit) plus a one-line tally: "N applicable, M N/A".
7. **Offer the opt-in fix.** Mimir edits nothing until the user chooses. Present: "Apply fixes? all / criticals only / a subset / none. Fixes run on a `mimir/<mode>` branch, one commit per fix; your working tree and main stay untouched until you review and merge."

#### App audit fix mode (only after the user opts in)

The sole path where Mimir changes project code, and only with explicit consent. Apply only the findings the user approved.

1. If the working tree is dirty, commit it first ("wip before mimir <mode> fixes") so each fix stays isolated.
2. `git checkout -b mimir/<mode>` (resume it if it already exists). Never commit fixes to `main`/`master`.
3. For each approved finding, in severity order: apply the remediation, verify lightly (run the project's typecheck/lint/test script if one exists; otherwise re-read the changed files — do **not** run a production build), then `git add -A && git commit -m "mimir <mode>: <short title>"`. One finding = one commit.
4. For **security** fixes specifically, stay conservative: never weaken a real control to make a check "pass", and if a fix to auth, crypto, or access-control can't be applied safely, leave it, note why, and move on. A bad security "fix" can be worse than the finding.
5. When done, summarize what was applied, what was skipped and why, and the branch name. Tell the user to review the branch and merge when satisfied. Never force-push; never merge to `main` yourself.

## Output Shape

```
Mimir's report — 2026-05-26 09:51

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

1. **Mimir is read-only by default.** The environment audit writes nothing except `--snapshot-baseline`, and only when the user explicitly asks for it. The app audit writes its findings report under `~/.config/mimir/reports/` and never touches the audited project during review. The one path that edits project code is **app audit fix mode**, which runs only after the user explicitly opts in, only on a `mimir/*` branch, one commit per fix — never on `main`, never the working tree, never without consent.
2. **Never auto-rotate credentials.** Rotation breaks every consumer of that token; only the user can sequence that.
3. **Never auto-rewrite git history.** `git filter-repo` is destructive and forces every collaborator to re-clone. Report-only.
4. **Never auto-PATCH Vercel projects.** Mistaken SSO toggles can expose internal dashboards.
5. **Never auto-change repo visibility.** Public/private is a deliberate business decision.
6. **Never auto-apply `npm audit fix`.** Major-version bumps can break the build.
7. **Never auto-uninstall a skill.** A risky-pattern flag is a prompt for the user to look, not a verdict.
8. **Always re-read the baseline before re-snapshotting.** A baseline written during a compromised session locks the compromise in.
9. **Use the JSON output when invoking from a Claude session.** Human output is for terminal use.

## Adding a Check

1. Add a `check_<name>()` function to `scripts/mimir.py` returning `(findings, actions)`.
2. Register it in the `CHECKS` dict.
3. Add a row to the "What Mimir Audits" table above.
4. Add reference data (regex patterns, etc.) under `reference/`.

## Adding or Updating an App Check

App-audit checks live as data in `reference/app_checks/{security,performance,ui}.md`, one `### N. Title  ·  **severity: ...**` block each (title, then the `*Area / Why it matters*` line, then what to look for and the fix). To add or edit a check, change the file directly — no code change needed. Keep each check self-contained. When a check overlaps another mode or the environment audit, add a `> **Dedup note:**` line naming the canonical home so it is not double-reported. Severity is the default for the class; the review pass adjusts it per instance. Renumber only if you must; the modes read top-to-bottom, not by index.

## Adding a Secret Pattern

Edit `reference/secret_patterns.json` (bundled defaults) or add to `extra_secret_patterns` in `~/.config/mimir/config.json` (user-specific). Each entry needs `name`, `regex`, and `severity` (`critical`, `high`, `medium`, `low`). Test the regex against a real-looking sample value first.

## Adding a Trusted Skill Remote

Edit `reference/skill_risk_patterns.json` and append the URL substring to `trusted_remotes`. Anything matching that substring on `git config --get remote.origin.url` is considered vetted.
