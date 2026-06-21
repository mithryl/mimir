<p align="center">
  <img src="assets/mimir-logo.png" alt="Mimir" width="320" />
<h1 align="center">Mimir</h1>

<p align="center">
  <a href="https://github.com/sponsors/mithryl"><img src="https://img.shields.io/badge/Sponsor-%E2%9D%A4-db61a2?logo=githubsponsors&logoColor=white" alt="Sponsor mithryl" /></a>
</p>

---

A security audit skill for Claude Code environments. Mimir audits two surfaces on demand: your **machine and accounts** (settings, secrets, Vercel/GitHub posture, supply chain, tamper, installed skills) and a **project's source code** (security, performance, UI/UX). It reports findings with exact remediations and never changes anything without your explicit say-so.

Mimir does not block, throttle, or change your workflow. It runs when you call it, reports what it found, and waits. The environment audit is fully read-only; app-code fixes happen only when you opt in, on a dedicated branch.

## Quick start

After installing (see [Install](#install)), open any Claude Code session and pick the style you prefer:

**Just run it** — uses sane defaults, no setup:
> summon mimir and do a full audit

**Walk me through it** — Mimir asks 4 onboarding questions, saves your config, then runs:
> summon mimir

Either way, you'll see a prioritized findings report. Mimir is **read-only** — every finding includes the exact remediation, but Mimir never writes to disk or changes settings without your explicit say-so.

## What it checks

| Check | Looks for |
|---|---|
| **settings** | bypassPermissions state, dangerous `additionalDirectories`, wildcard Read/Edit/Write |
| **secrets** | Committed `.env` files, plaintext API tokens (21 patterns: Anthropic, OpenAI, GitHub, Vercel, HubSpot, Notion, AWS, Stripe, Slack, Twilio, SendGrid, etc.), gitignore baseline coverage |
| **vercel** | Cron projects with SSO protection (silently breaks crons) |
| **github** | Repos under your account that are public when they probably shouldn't be |
| **supply** | `npm audit` critical/high vulns, missing lockfiles |
| **cooldown** | Missing package-install cooldown policy (no `minimumReleaseAge` window). Defense against self-propagating npm/PyPI worms that steal tokens and republish themselves minutes after a version goes live. |
| **tamper** | Diffs `~/.claude/CLAUDE.md`, `settings.json`, and every installed `SKILL.md` against a baseline. Flags persistence vectors. |
| **skills** | Inspects every installed skill's `SKILL.md` and scripts for risky patterns (pipe-to-shell, eval, `.env` reads, settings tampering, reverse-shell shapes) and checks git provenance |
| **rotation** | `.env` files older than N days (default 180) |

## App audits (project code)

Beyond the machine/account audit above, Mimir reviews a single project's **source code** against three checklists an LLM builder commonly ships past — 100 checks each:

| Trigger | Reviews for |
|---|---|
| `summon mimir to audit security` · `/mimir security` | In-code vulnerability classes: auth, sessions/tokens, access control, injection, XSS, CSRF, input validation, secrets, crypto, API limits, file uploads, logging |
| `summon mimir to audit performance` · `/mimir performance` | Rendering & re-renders, perceived load, images/fonts, bundles, network/API, caching, database, backend/concurrency |
| `summon mimir to audit the UI` · `/mimir ui` | Design-system consistency, responsive layout, typography, accessibility, motion, forms, feedback states, navigation, data display |

App audits run against the current project (or a path you name), not the whole machine. They are **review-and-report by default**: Mimir lists findings by severity with the exact fix and writes a report under `~/.config/mimir/reports/`, touching nothing in your project. If you then opt in, Mimir applies the fixes you approve on a dedicated `mimir/<mode>` branch, one commit per fix — your working tree and `main` stay untouched until you review and merge. Security findings are reported first and never auto-rewritten unattended, since a bad fix to auth or crypto can be worse than the flaw.

The checklists live as editable data in `reference/app_checks/`; add or change a check by editing the file.

## Install

```bash
git clone https://github.com/mithryl/mimir.git ~/.claude/skills/mimir
```

That's it. Claude Code auto-discovers skills under `~/.claude/skills/`. Open any Claude Code session and type `/mimir`.

Optional CLIs that activate additional checks if present:
- [`vercel`](https://vercel.com/docs/cli) — activates the `vercel` check
- [`gh`](https://cli.github.com) — activates the `github` check
- `npm` — activates the supply-chain check on Node projects

Mimir degrades gracefully when a CLI is missing — that check is skipped and reported as `info`.

## Use

Inside any Claude Code session:

```
/mimir
```

Or trigger phrases: "summon mimir", "run a security audit", "am I exposed", "what's my risk", "is this safe", "audit my setup". For project-code review: "summon mimir to audit security / performance / the UI" (or `/mimir security|performance|ui`).

Direct CLI invocation (for cron jobs, CI, terminal use):

```bash
# Default: run all checks, read-only, human-readable output
python3 ~/.claude/skills/mimir/scripts/mimir.py --check all

# JSON for programmatic consumers
python3 ~/.claude/skills/mimir/scripts/mimir.py --check all --json

# Specific checks only
python3 ~/.claude/skills/mimir/scripts/mimir.py --check secrets,supply

# Scope a run to one folder instead of the whole machine (repeatable)
python3 ~/.claude/skills/mimir/scripts/mimir.py --path ~/projects/my-app
python3 ~/.claude/skills/mimir/scripts/mimir.py --path ~/projects/a --path ~/projects/b

# Write the tamper-detection baseline (the only write operation)
python3 ~/.claude/skills/mimir/scripts/mimir.py --snapshot-baseline
```

## Configure

Mimir reads `~/.config/mimir/config.json` if it exists, otherwise uses sensible defaults. Override the file location with `$MIMIR_CONFIG`.

```json
{
  "scan_roots": ["~/projects", "~/work"],
  "max_walk_depth": 6,
  "env_rotation_days": 180,
  "extra_env_paths": ["/etc/myapp/.env.production"],
  "exempt_public_repos": ["my-org/intentionally-public-repo"],
  "extra_secret_patterns": [
    {"name": "Internal token", "regex": "INT-[A-Z0-9]{32}", "severity": "critical"}
  ],
  "extra_skip_dirs": ["vendor", "third_party"]
}
```

| Key | Type | Default | Purpose |
|---|---|---|---|
| `scan_roots` | string[] | `["~"]` | Directories Mimir walks looking for git repos. Use ~ for expansion. |
| `max_walk_depth` | int | `6` | Depth limit per scan root. |
| `env_rotation_days` | int | `180` | Threshold for `rotation` check. |
| `extra_env_paths` | string[] | `[]` | Explicit `.env` files to age-check beyond auto-discovered ones. |
| `exempt_public_repos` | string[] | `[]` | `owner/name` pairs to skip in the public-repo finding. |
| `extra_secret_patterns` | object[] | `[]` | Custom token patterns. Each needs `name`, `regex`, `severity`. |
| `extra_skip_dirs` | string[] | `[]` | Directory names to skip during repo discovery. |

## Severity tiers

| Tier | Meaning | Response |
|---|---|---|
| **CRITICAL** | Active compromise or imminent breach. Live credential exposed. | Stop everything; fix today. |
| **HIGH** | Real exposure, posture problem that will bite. | Fix this week. |
| **MEDIUM** | Real risk, contained. Hygiene gap. | Fix this month. |
| **LOW** | Notional. Worth knowing. | Address opportunistically. |
| **INFO** | State recorded for future-run context. | None — receipt only. |

## Hard rules

During the **environment audit**, Mimir will never:

1. Write to disk except via the explicit `--snapshot-baseline` command — and even then, only the tamper baseline file. (The **app audit** writes only a findings report under `~/.config/mimir/reports/` and never edits your project during review; the one path that edits project code is app-audit fix mode, which runs only after you opt in, only on a `mimir/*` branch.)
2. Auto-rotate credentials — rotation breaks every consumer, only you can sequence that.
3. Auto-rewrite git history — destructive, forces every collaborator to re-clone.
4. Auto-PATCH Vercel projects — mistaken toggles can expose internal dashboards.
5. Auto-change repo visibility — public/private is a deliberate business decision.
6. Auto-apply `npm audit fix` — major-version bumps can break the build.
7. Auto-uninstall a skill — risky-pattern flags prompt you to look, not Mimir to verdict.
8. Modify your settings.json, deny rules, .gitignore, or accounts on its own — every environment remediation is reported with the exact command for you to run. (App-audit fix mode is the sole consented exception, and only on a `mimir/*` branch.)

## Extend

**Add a check:** define `check_<name>() -> (findings, [])` in `scripts/mimir.py`, register in the `CHECKS` dict, document in `SKILL.md` and this README. Checks must be pure functions — no disk writes, no network mutations.

**Add a secret pattern:** edit `reference/secret_patterns.json` (PR-able) or `extra_secret_patterns` in your config (personal).

**Add a trusted skill remote:** edit `reference/skill_risk_patterns.json` under `trusted_remotes`. Substring match against `git config --get remote.origin.url`.

## License

MIT. See [LICENSE](LICENSE).

## Limitations

- Secret scanning is HEAD-only. It does not search git history. Use [`trufflehog`](https://github.com/trufflesecurity/trufflehog) or `git filter-repo` for that.
- The `tamper` check fingerprints by SHA-256 of the file. It cannot tell legitimate edits from malicious ones — you have to look at each diff and decide.
- The `skills` check inspects content with regex. Sophisticated obfuscation will evade it.
- Mimir runs as you. It has every permission you have. It cannot detect compromises that have already escalated past your shell.
