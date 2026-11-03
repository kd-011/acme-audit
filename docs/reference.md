# Reference

## Command line

```
acme-audit [--root DIR] [options]
acme-audit demo [--json]
```

| Option | Meaning |
| --- | --- |
| `--root DIR` | Audit the machine tree under DIR. Default `/`, or the value of `ACME_AUDIT_ROOT`. `--root` wins when both are set. |
| `--json` | Print the report as JSON. See [json-schema.md](json-schema.md). |
| `--fail-on LEVEL` | Exit 1 only for findings at LEVEL or worse. `error`, `warn` or `info`. Default `info`, so any finding exits 1. |
| `--schedule FILE` | Use another schedule file in place of `data/schedule.json`. |
| `--lifetime DAYS` | Also test against a certificate lifetime of DAYS. Repeat it for more. `--lifetime 6` tests the short-lived profile. |
| `--version` | Print the version. |
| `--help` | Print the options. |

Exit codes: 0 when nothing at or above `--fail-on` was found, 1 when something was, 2 when the tool could not run (a root that is not a directory, an unknown option, a schedule file it cannot read).

A path the process is not allowed to read is reported once as a note and is never reported as missing. Run as root to include those paths.

Paths in the output are paths as the audited machine sees them, so `--root /mnt/backup` prints `/etc/letsencrypt/...`, not `/mnt/backup/etc/letsencrypt/...`. Symlinks are followed inside the root and never out of it.

## Severities

error: the renewal will not happen, or the hook that follows it will not run, on the lifetimes tested. warn: it works but leaves little room, or only breaks at the shorter of the lifetimes. info: worth knowing, nothing is broken by it.

## What each kind looks at

### HARDCODED-DAYS

Searches for a renewal threshold written as a number of days. The files searched are cron files, systemd service files that run a renewal command, the scripts those call, everything in `/usr/local/bin` and `/usr/local/sbin`, `bin`, `scripts` and `.local/bin` in each home, `cron.hourly` to `cron.monthly`, and `renewal-hooks`. A file is only searched when it mentions a client or a certificate (certbot, acme.sh, lego, letsencrypt, ACME, renew, `openssl x509`). Comment lines are skipped. A line is reported when it has one of these:

- `find ... -mtime +N`: read as "N days after issue", judged against each lifetime.
- `openssl x509 -checkend S`, with S in seconds or written as `$((N*86400))`: read as "expires within S seconds", judged against each lifetime.
- One of the numbers Let's Encrypt names (83, 80 and 60, from `facts.hardcoded_numbers`) next to a day word such as `days`, `mtime`, `expir` or `age`. The direction is unknown here, so the finding says to check whether the number counts from issue or from expiry.

A line already reported by a client check (for example `lego renew --days 60`) is not reported twice.

### RENEW-WINDOW

A setting in a client's own configuration that sets when it renews.

| Client | Setting | Read as |
| --- | --- | --- |
| certbot | `renew_before_expiry` in the renewal file | days before expiry. A bare number is days. Units certbot's parser accepts (`2 weeks`, `3 months`) are read. |
| acme.sh | `Le_RenewalDays` in the domain conf, `--days` on a command line | days after issue. acme.sh renews one day early and never later than one day before expiry, and the audit uses the same rule. |
| lego | `renew --days N` on a command line | days before expiry. `--dynamic` supersedes it and is not flagged. |
| Caddy | `renewal_window_ratio` | fraction of the lifetime left at renewal |
| Traefik | `certificatesDuration` in hours | Traefik turns the duration into a renew-before period with a fixed table, copied into the schedule file |

For each lifetime in the schedule the audit works out the day the renewal fires and how many days remain to retry. It reports `error` when the setting renews on every run or leaves one day or less, and `warn` when it leaves fewer than `policy.min_margin_days`. The severity is the worst result over all lifetimes tested.

### TIMER-INFREQUENT

Looks at what runs the renewal. For systemd timers it reads `OnCalendar` (shortcuts such as `daily` and `weekly`, weekday names, day and month lists, ranges and steps; the time of day is ignored) and `OnUnitActiveSec` and `OnUnitInactiveSec`. For cron it reads five-field lines, the `@` shortcuts, `/etc/anacrontab` and the `cron.daily` family. Both are expanded to the days they fire on across two years, plus the times of day, and the longest gap is what counts. A job that fires several times a day has a gap under one day.

A run gap is too long when the renewal window, taken as the last third of the lifetime, would hold fewer than `policy.min_runs_in_renew_window` runs. With the schedule as shipped that means about 5 days for 45-day certificates.

It also reports, as an error:

- A timer that runs a renewal command and is not enabled: nothing in a `.wants` directory starts it, or it is masked.
- certbot lineages or acme.sh domains and no timer or cron entry anywhere that runs them. The message says that a scheduler in a container or on another host is invisible to this audit.

Caddy's `renew_interval` goes through the same gap test.

### HOOK-MISSING and HOOK-NOT-EXECUTABLE

Hooks in certbot renewal files (`pre_hook`, `post_hook`, `renew_hook`, `deploy_hook`, `manual_auth_hook`), in acme.sh domain confs (`Le_PreHook`, `Le_PostHook`, `Le_RenewHook`, `Le_ReloadCmd`, which acme.sh stores base64 encoded and the audit decodes), on lego's `--renew-hook`, and on certbot's hook flags in cron lines and scripts. The program a hook starts with is looked up: an absolute path must exist and have an execute bit, and a bare name is searched for in `/usr/local/sbin`, `/usr/local/bin`, `/usr/sbin`, `/usr/bin`, `/sbin` and `/bin` under the root. Shell built-ins, `$VARIABLE` words and relative paths are skipped because they cannot be resolved from text.

Files in `/etc/letsencrypt/renewal-hooks/pre`, `deploy` and `post` are checked one by one. A dangling symlink is HOOK-MISSING. A file with no execute bit is HOOK-NOT-EXECUTABLE, and certbot does not run it.

Whether a hook that exists also succeeds is not checked.

### ACMEJSON-PERMS

For each Traefik resolver the `storage` path is resolved (relative paths next to the static config, then from `/`). If the file has any group or other permission bit set, Traefik will not use it. The audit reports the mode.

### DEAD-AUTH

The renewal cannot get a usable certificate:

- certbot: a renewal file that cannot be parsed or lacks `cert`, `privkey`, `chain` or `fullchain`; no `[renewalparams]`; no `authenticator`; the `manual` authenticator with no `manual_auth_hook`; a `webroot` path that is not on this machine (warn); `autorenew = False` (warn).
- Traefik: a resolver with none of `tlsChallenge`, `httpChallenge` and `dnsChallenge`.
- Any client pinned to the Let's Encrypt staging CA (warn): certbot `server`, acme.sh `Le_API`, Caddy `acme_ca`, `dir` or `ca`, Traefik `caServer`.

### OLD-CLIENT

certbot older than the first release that checks ARI, and acme.sh older than the first release that has ARI code. Versions come from the schedule. The certbot version is read from an installed `certbot-X.Y.Z.dist-info` directory, or failing that from the `version` that certbot wrote in the renewal file. The acme.sh version is the `VER=` line of its script. lego, Caddy and Traefik versions cannot be read from files, so they are not checked.

## Files read

certbot: `/etc/letsencrypt/renewal/*.conf`, `/etc/letsencrypt/renewal-hooks/{pre,deploy,post}/*`, and `certbot-*.dist-info` under `/usr/lib`, `/usr/local/lib` and `/opt/eff.org/certbot/venv/lib`.

acme.sh: `.acme.sh/acme.sh` and `.acme.sh/*/*.conf` in `/root` and in each directory under `/home`.

Caddy: `/etc/caddy/Caddyfile`, `/usr/local/etc/caddy/Caddyfile`, `/etc/Caddyfile`, and files they `import` (up to three levels, `*` globs allowed).

Traefik: `traefik.yml`, `traefik.yaml` and `traefik.toml` in `/etc/traefik`, `/etc`, `/usr/local/etc/traefik`, `/opt/traefik` and `/srv/traefik`, and each acme.json they name.

Scheduling: `/etc/crontab`, `/etc/cron.d/*`, `/var/spool/cron/crontabs/*`, `/var/spool/cron/*`, `/etc/anacrontab`, `/etc/cron.{hourly,daily,weekly,monthly}/*`, and `.timer` and `.service` units in `/etc/systemd/system`, `/etc/systemd/user`, `/lib/systemd/system`, `/usr/lib/systemd/system` and `.config/systemd/user` in each home.

## data/schedule.json

| Key | Holds |
| --- | --- |
| `targets` | The lifetimes the checks test against: `days` and a `label`. |
| `facts` | Dates and numbers from Let's Encrypt's announcement: the date the default moves to 64 days, the two-thirds rule, the numbers to grep for. |
| `lifetimes` | The profiles Let's Encrypt lists and their lifetime in hours. Informational. |
| `clients` | Per client: the release that changed renewal timing, the release that added ARI, and defaults the messages quote. |
| `policy` | Two choices of this tool, not facts: `min_margin_days` and `min_runs_in_renew_window`. |
| `sources` | For each source id: the URL, the date it was read, and what it says. |

`node --test` checks that every source has a URL and a date and that every source a value cites is listed.
