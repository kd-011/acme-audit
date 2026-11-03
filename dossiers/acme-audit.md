---
slug: acme-audit
name: acme-audit
repo: .
status: building
last_verified: 2026-11-03
tags: [cli, node, tls, acme, lint]
---

A command line tool that reads how a machine renews its Let's Encrypt certificates and reports what will break under shorter lifetimes. These claims are the README's main promises, each tied to the code that keeps it.

## Features

- Runs on Node 22 or newer and installs one command, `acme-audit`. <!-- src: package.json:12, package.json:14 -->
- Has no runtime or development dependencies, only Node built-ins. <!-- src: package.json -->
- Exits 0 when nothing at or above `--fail-on` was found, 1 when something was, and 2 when it could not run. <!-- src: src/cli.mjs:82-83 -->
- The audit root comes from `--root`, then `ACME_AUDIT_ROOT`, then `/`. <!-- src: src/cli.mjs:30 -->
- Lifetimes, dates, the numbers to grep for and the client facts come from `data/schedule.json` and are validated on load. <!-- src: src/schedule.mjs:6-20 -->
- A renewal setting is an error when it renews on every run or leaves one day or less, and a warning when it leaves fewer days than `policy.min_margin_days`. <!-- src: src/window.mjs:25-26 -->
- A run gap is too long when the last third of the lifetime would hold fewer runs than `policy.min_runs_in_renew_window`. <!-- src: src/window.mjs:46-60 -->
- Traefik's acme.json is flagged when any group or other permission bit is set. <!-- src: src/checks/traefik.mjs:108 -->
- A hook is flagged when its absolute path is missing or not executable, or when a bare command name is on none of six standard PATH directories under the root. <!-- src: src/hooks.mjs:5, src/hooks.mjs:20-36 -->
- acme.sh hook values are decoded from their base64 wrapping before they are checked. <!-- src: src/checks/acmesh.mjs:7-19 -->

## Architecture

- Every file read goes through a `Tree` that resolves symlinks, including ones in the middle of a path, against the audited root and gives up after 20 hops. <!-- src: src/fsx.mjs:21-45 -->
- Schedules are expanded to the days they fire on across 800 days from 2027-01-01, and the longest gap is what counts. <!-- src: src/cron.mjs:4-5 -->
- Only the demo tree builder writes files, and it refuses to remove a directory that is not its own temp dir. <!-- src: src/demo-tree.mjs:33, src/demo-tree.mjs:97-100 -->

## Deploy

- CI runs `node --test` on Node 22 and 24 for every pull request and once a week. <!-- src: .github/workflows/ci.yml:9-10, .github/workflows/ci.yml:24 -->
- Dependabot opens grouped weekly updates for GitHub Actions and qualifying ones merge automatically once CI is green. <!-- src: .github/dependabot.yml, .github/scripts/automerge-eligible.mjs -->

## Generated facts

<!-- auto:start -->
- package: acme-audit 0.1.0
- npm scripts (1): test
<!-- auto:end -->
