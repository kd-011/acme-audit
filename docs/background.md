# Background and sources

Everything acme-audit says about Let's Encrypt or a client was read on a page while this tool was built, on 2026-11-03. This file lists those pages and what was taken from each. The same entries, with the exact wording used, are in [data/schedule.json](../data/schedule.json). Anything I could not find on a page is left out.

## The change

Source: https://letsencrypt.org/2026/10/07/64-day-certs, published 2026-10-07, read 2026-11-03.

- On 2027-02-10 all Let's Encrypt subscribers move to certificates with 64 day lifetimes by default.
- The staging environment issues 64-day certificates from 2026-10-14, for testing.
- The last 90-day certificate is expected to expire on 2027-05-11.
- The post says this lays the groundwork for default lifetimes of 45 days in 2028. It gives no day for that.
- If renewals are automated and the client supports ACME Renewal Info (ARI), the post says you should be all set.
- If renewals are hard-coded to a number of days before expiry, update them to renew at approximately two thirds of the lifetime.
- To find hardcoded values: "Grep for common hardcoded numbers like 83, 80 or 60 in cron jobs, wrapper scripts and runbooks".
- Authorization reuse shrinks, which matters only to clients that rely on reusing a validation. The post names no client. acme-audit does not look at it.

The post does not list client versions. The two-thirds figure is where `facts.renew_at_fraction_of_lifetime` comes from. The numbers 83, 80 and 60 are `facts.hardcoded_numbers`. The 64 and 45 in `targets` come from the post. The 45 is labelled "planned for 2028" because the post gives a year and nothing finer.

## Profiles

Source: https://letsencrypt.org/docs/profiles/, read 2026-11-03.

The page lists `classic` at 90 days (the default), `tlsserver` at 45 days, and `shortlived` at about 6 days (160 hours). `tlsclient` is listed as no longer available as of 2026-07-08. The page says which profiles are on offer depends on the environment and that the ACME directory is the authority. It publishes no schedule for the default. The 6-day lifetime is why `--lifetime 6` exists: it is not tested by default because it is opt-in.

## Demand

Source: https://www.virtualizationhowto.com/2026/10/lets-encrypt-is-shortening-certificate-lifetimes-is-your-home-lab-ready/, published 2026-10-15, read 2026-11-03.

The post says "since we may have built automations around the 90 day window, we may need to tweak these for the new 64 day expirations". For checking it recommends `systemctl list-timers --all`, `sudo certbot certificates`, `sudo certbot renew --dry-run` (and `--run-deploy-hooks`), Traefik's version and logs, and Uptime Kuma. It names no tool that reads the renewal configuration of several clients.

## Clients

certbot. Source: the project changelog, https://raw.githubusercontent.com/certbot/certbot/main/certbot/CHANGELOG.md, read 2026-11-03.

- 4.0.0 (2025-04-07): a certificate renews with a third of its lifetime left (a half when the lifetime is under 10 days), where before it was a fixed 30 days before expiry. `renew_before_expiry` still overrides it.
- 4.1.0 (2025-06-10): ARI support. An early ARI answer overrides a later `renew_before_expiry`.
- 4.1.1 (2025-06-12): no ARI check for lineages with autorenew set to False.

certbot behaviour read from its source, https://github.com/certbot/certbot/tree/main/certbot/src/certbot/_internal, read 2026-11-03:

- `renewal.py`: a renewal file that is broken, has no `renewalparams` or has no `authenticator` is logged as an error and skipped. It is counted as a parse failure and the run exits non-zero. That makes a broken file loud on the command line, and an unattended run still never renews that certificate.
- `storage.py`: a file missing `cert`, `privkey`, `chain` or `fullchain` is treated as broken. `renew_before_expiry` is a time interval such as `10 days` or `3 weeks`, and a bare integer means days. certbot writes its own `version` into the file.
- `hooks.py`: `list_hooks` returns only executable files, in sorted order, for the directories `pre`, `deploy` and `post`.

certbot documentation, https://eff-certbot.readthedocs.io/en/stable/using.html, read 2026-11-03: a deploy hook runs only after a successful renewal. With `--dry-run`, deploy hooks do not run unless `--run-deploy-hooks` is given. If a hook exits non-zero the error is printed and the renewal is attempted anyway. The `manual` authenticator does not support automatic renewal unless it is combined with `--manual-auth-hook`.

acme-audit reports such a file as DEAD-AUTH and says certbot skips it. It does not say the skip is silent, because the source shows it is logged.

acme.sh. Source: the script at tag 3.1.6, https://github.com/acmesh-official/acme.sh/blob/3.1.6/acme.sh, and the tags 3.1.2, 3.1.3 and 3.1.5, read 2026-11-03.

- `DEFAULT_RENEW` is 30. `Le_RenewalDays` is written to the domain conf only when `--days` was passed.
- The next renewal is the creation time plus the days, minus one day, and never later than one day before expiry.
- ARI code (`ACME_RENEWAL_INFO`) is in tag 3.1.3 and not in 3.1.2. 3.1.3 was published 2026-04-28. Its release notes do not mention ARI, so the version comes from the source.
- The 3.1.5 release notes say an explicit `--days` or `--valid-to` now outranks the ARI window.
- Hook values and the reload command are stored base64 encoded between `__ACME_BASE64__START_` and `__ACME_BASE64__END_`. The cron line it installs runs `acme.sh --cron` four times a day.

lego. Sources: https://github.com/go-acme/lego/blob/master/CHANGELOG.md and https://github.com/go-acme/lego/blob/master/cmd/cmd_renew.go, read 2026-11-03.

- v4.12.0 (2023-05-28): initial ARI implementation. v4.20.2 (2024-11-11): the CLI checks ARI unless it is disabled.
- `renew --days` is the number of days left on a certificate to renew it, default 30. `--dynamic` renews with a third of the lifetime left and supersedes `--days`. `--ari-disable` turns the ARI check off. `--renew-hook` runs only when a certificate was renewed.

Caddy. Sources: https://caddyserver.com/docs/caddyfile/options and https://github.com/caddyserver/caddy/releases/tag/v2.8.0, read 2026-11-03.

- `renewal_window_ratio` defaults to 0.3333 as a global option. `renew_interval` defaults to 10m. `acme_ca` defaults to ZeroSSL and Let's Encrypt production.
- Caddy 2.8.0 (2024-05-29) added ARI support.

Traefik. Sources: https://doc.traefik.io/traefik/reference/install-configuration/tls/certificate-resolvers/acme/, https://github.com/traefik/traefik/blob/master/pkg/provider/acme/provider.go and `local_store_unix.go` in the same directory, read 2026-11-03.

- `certificatesDuration` is in hours, defaults to 2160, and is used only to work out renewal dates. By default Traefik starts renewing 30 days before expiry.
- `getCertificateRenewDurations` maps the duration to a renew-before period with a table. It is copied into `clients.traefik.renew_periods`.
- `CheckFile` returns an error when the mode of acme.json has any group or other bit set: "permissions ... are too open, please use 600".
- ARI: the documentation page does not mention it, and I found no mention in the release notes. I could not confirm whether Traefik checks ARI, so acme-audit makes no claim either way.

## Prior art

On 2026-11-03 I searched GitHub (`gh search repos`) for the obvious phrasings, "acme audit", "certbot renewal", "letsencrypt renewal audit", "acme renewal lint" and "certificate lifetime renewal audit", and searched the web three times for a tool that audits renewal setups across clients. The only repository with a matching name was an audit-logging module for an ERP system. I found no tool that does this across clients.
