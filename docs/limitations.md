# What acme-audit does not check

Read this before you trust a clean run.

## Where the demand comes from

The reason to run this now is the change to 64-day certificates on 2027-02-10, and the 45-day default planned for 2028. The evidence is one announcement from Let's Encrypt that tells people to grep by hand, and one blog post that tells readers to tweak their automations. I have not measured how many people want a tool for it, and I have no usage numbers. After the change is done the same checks still answer "will my renewals fire", but whether anyone keeps running it is a guess.

## It reads files, not machines

- It sees only what is under the root. A scheduler in a container, on another host, in a control panel, in a Kubernetes cron job or in a service manager other than systemd and cron is invisible to it. When it finds certificates and no scheduler it says so, and the message says what it cannot see.
- A timer or cron line that sits in a file is treated as active. A cron line guarded by a condition (Debian's certbot cron entry only runs when systemd is absent) is read as if it always runs.
- Time zones, `RandomizedDelaySec`, `Persistent=` and the order in which units start are ignored. Only which days a schedule fires on matters here.
- It reads `/root` and each directory under `/home`. Another layout, such as a home directory somewhere else, is not found.
- Only the paths listed in [reference.md](reference.md) are searched. A Caddy or Traefik config kept elsewhere, such as a file inside a Docker volume, is not read unless you point `--root` at a tree that contains it at the usual path.

## It does not run anything

- It does not check that a hook succeeds. A hook that exists and is executable can still fail, and `certbot renew --dry-run` will not run a deploy hook unless you add `--run-deploy-hooks`.
- It does not look at the certificates on disk, so it cannot tell you one is about to expire or has the wrong lifetime.
- It does not test the network, DNS, ports or the challenge.
- It does not check that your client is using ARI. For certbot and acme.sh it compares a version number. For lego, Caddy and Traefik it makes no version check, because a version cannot be read from the files.
- Whether Traefik checks ARI is not known to this tool. I could not find it in the documentation or the release notes.

## What it does not read

- Traefik settings given as command line flags or labels in a Docker Compose file, and Caddy JSON config. Only the Caddyfile and Traefik's YAML and TOML static config are parsed. The YAML reader handles nested mappings and lists, not anchors or flow style beyond `{}`.
- Windows, macOS launchd and BSD-specific scheduler layouts. I develop and test on Linux.
- Other ACME clients and other CAs. dehydrated, win-acme, Certify, step-ca clients and the rest are not looked at. A CA other than Let's Encrypt has its own lifetime schedule that is not in `data/schedule.json`.
- Authorization reuse, which Let's Encrypt says also changes. The post says most users need no change.

## Guesses in the checks

- The hardcoded-days search is textual. A threshold built from variables, or written in a unit I do not know about, is missed. A line that mentions one of the named numbers next to a day word is reported even when the number means something else, which is why that finding says the direction is unknown.
- A file is only searched for hardcoded numbers when it mentions a client or certificate word. A wrapper that does not mention any of them is skipped.
- The margins are my choices: at least 7 days of retries after a failure, and at least 3 runs inside the renewal window. They are in `policy` in the schedule file. Someone with a daily job and a strong alerting setup may reasonably accept less.
- The renewal window used for the timer check is the last third of the lifetime, taken from the "about two thirds" in Let's Encrypt's post. A client with ARI may be told a different time.
- The 6-day short-lived profile is not tested by default. Use `--lifetime 6`.

## Not a fix

It reports. It never edits a file, restarts a service or runs a client, and there is no mode that does.
