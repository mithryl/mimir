<p align="center">
  <img src="assets/mimir-logo.png" alt="Mimir" width="320" />
</p>

<h1 align="center">Mimir</h1>

---

A security audit skill for Claude Code environments. Summonable on demand, auto-fixes safe things, reports the rest.

Mimir does not block, throttle, or change your workflow. It runs when you call it, prints what it found, and waits.

## Quick start

After installing (see [Install](#install)), open any Claude Code session and pick the style you prefer:

**Just run it** — uses sane defaults, no setup:
> summon mimir and do a full audit

**Walk me through it** — Mimir asks 4 onboarding questions, saves your config, then runs:
> summon mimir

Either way, you'll see a prioritized findings report. Mimir auto-fixes the safe stuff (deny rules, gitignore baseline, tamper snapshot) and waits for your call on the risky stuff.

## What it checks

| Check | Looks for | Auto-fix |
|---|---|---|
| **settings** | bypassPermissions state, missing deny rules for catastrophic ops, dangerous `additionalDirectories`, wildcard Read/Edit/Write | Adds missing deny rules |
| **secrets** | Committed `.env` files, plaintext API tokens (21 patterns: Anthropic, OpenAI, GitHub, Vercel, HubSpot, Notion, AWS, Stripe, Slack, Twilio, SendGrid, etc.), gitignore baseline coverage | Appends gitignore entries |
| **vercel** | Cron projects with SSO protection (silently breaks crons) | Reports |
| **github** | Repos under your account that are public when they probably shouldn't be | Reports |
| **supply** | `npm audit` critical/high vulns, missing lockfiles | Reports |
| **tamper** | Diffs `~/.claude/CLAUDE.md`, `settings.json`, and every installed `SKILL.md` against a baseline. Flags persistence vectors. | Writes initial baseline |
| **skills** | Inspects every installed skill's `SKILL.md` and scripts for risky patterns (pipe-to-shell, eval, `.env` reads, settings tampering, reverse-shell shapes) and checks git provenance | Reports |
| **rotation** | `.env` files older than N days (default 180) | Reports |

## Install

```bash
git clone https://github.com/Mithryl-Labs/mimir.git ~/.claude/skills/mimir
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

Or trigger phrases: "summon mimir", "run a security audit", "am I exposed", "what's my risk", "is this safe", "audit my setup".

Direct CLI invocation (for cron jobs, CI, terminal use):

```bash
# Default: run all checks, apply safe auto-fixes, human-readable output
python3 ~/.claude/skills/mimir/scripts/mimir.py --check all --autofix-safe

# JSON for programmatic consumers
python3 ~/.claude/skills/mimir/scripts/mimir.py --check all --json

# Specific checks only
python3 ~/.claude/skills/mimir/scripts/mimir.py --check secrets,supply

# Re-baseline tamper detection after confirming a config change was intentional
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

Mimir will never:

1. Auto-rotate credentials — rotation breaks every consumer, only you can sequence that.
2. Auto-rewrite git history — destructive, forces every collaborator to re-clone.
3. Auto-PATCH Vercel projects — mistaken toggles can expose internal dashboards.
4. Auto-change repo visibility — public/private is a deliberate business decision.
5. Auto-apply `npm audit fix` — major-version bumps can break the build.
6. Auto-uninstall a skill — risky-pattern flags prompt you to look, not Mimir to verdict.
7. Re-baseline tamper detection without explicit `--snapshot-baseline` — a baseline written during a compromised session locks the compromise in.

## Extend

**Add a check:** define `check_<name>(autofix) -> (findings, actions)` in `scripts/mimir.py`, register in the `CHECKS` dict, document in `SKILL.md` and this README.

**Add a secret pattern:** edit `reference/secret_patterns.json` (PR-able) or `extra_secret_patterns` in your config (personal).

**Add a deny rule:** edit `reference/deny_rules.json`.

**Add a trusted skill remote:** edit `reference/skill_risk_patterns.json` under `trusted_remotes`. Substring match against `git config --get remote.origin.url`.

## License

MIT. See [LICENSE](LICENSE).

## Limitations

- Secret scanning is HEAD-only. It does not search git history. Use [`trufflehog`](https://github.com/trufflesecurity/trufflehog) or `git filter-repo` for that.
- The `tamper` check fingerprints by SHA-256 of the file. It cannot tell legitimate edits from malicious ones — you have to look at each diff and decide.
- The `skills` check inspects content with regex. Sophisticated obfuscation will evade it.
- Mimir runs as you. It has every permission you have. It cannot detect compromises that have already escalated past your shell.
