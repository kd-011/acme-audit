# Changelog

Notable changes are listed here, newest first. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [semantic versioning](https://semver.org/).

## 0.1.0 - 2026-11-03

First version.

### Added

- `acme-audit [--root DIR]`: a read-only audit of certbot, acme.sh, lego, Caddy and Traefik renewal setups, systemd timers, cron files and wrapper scripts.
- Eight kinds of finding: HARDCODED-DAYS, HOOK-MISSING, HOOK-NOT-EXECUTABLE, RENEW-WINDOW, TIMER-INFREQUENT, ACMEJSON-PERMS, DEAD-AUTH and OLD-CLIENT.
- `demo`, which audits a bundled fake machine with one of each.
- `--json` with a documented schema, exit codes 0, 1 and 2, `--fail-on`, `--version`, `--schedule` and `--lifetime`.
- `data/schedule.json`, which holds the lifetimes, the dates and the client facts with the page each was read from, so the checks can be updated by pull request.
- Documentation: a reference, the background and sources, the JSON schema and a list of what is not checked.
