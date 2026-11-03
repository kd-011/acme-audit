# JSON output

`acme-audit --json` prints one JSON object. The shape is stable within a major version. A key is only added in a minor version, and a key that is removed or changes meaning bumps `schema`.

```json
{
  "tool": "acme-audit",
  "schema": 1,
  "version": "0.1.0",
  "root": "/",
  "schedule": {
    "checked": "2026-11-03",
    "targets": [
      { "days": 64, "label": "64-day default from 2027-02-10" },
      { "days": 45, "label": "45-day default planned for 2028" }
    ]
  },
  "summary": { "error": 1, "warn": 0, "info": 0, "total": 1 },
  "findings": [
    {
      "kind": "HOOK-MISSING",
      "severity": "error",
      "client": "certbot",
      "file": "/etc/letsencrypt/renewal/example.com.conf",
      "line": 16,
      "summary": "renew_hook runs /usr/local/bin/reload-nginx.sh, which does not exist on this machine",
      "why": "This hook is what reloads the service after a renewal. ...",
      "detail": { "field": "renew_hook", "command": "/usr/local/bin/reload-nginx.sh", "path": "/usr/local/bin/reload-nginx.sh", "role": "deploy" }
    }
  ],
  "notes": [],
  "scanned": {
    "certbot_lineages": 1, "acmesh_domains": 0, "lego_jobs": 0, "caddyfiles": 0,
    "traefik_configs": 0, "timers": 1, "cron_files": 0, "scripts": 0
  }
}
```

## Top level

| Key | Type | Meaning |
| --- | --- | --- |
| `tool` | string | Always `acme-audit`. |
| `schema` | integer | The schema version, currently 1. |
| `version` | string | The acme-audit version. |
| `root` | string | The root that was audited, as given. |
| `schedule.checked` | string | The date the schedule data was last checked against its sources. |
| `schedule.targets` | array | The lifetimes tested: `days` and `label`. |
| `summary` | object | Counts by severity and `total`. |
| `findings` | array | Sorted errors first, then warnings, then notes. Order within a severity follows discovery. |
| `notes` | array | Things that could not be read or understood: `{ "file", "message" }`. They do not affect the exit code. |
| `scanned` | object | How many of each thing were read. All zero means nothing under the root looked like an ACME setup. |

## Finding

| Key | Type | Meaning |
| --- | --- | --- |
| `kind` | string | One of `HARDCODED-DAYS`, `HOOK-MISSING`, `HOOK-NOT-EXECUTABLE`, `RENEW-WINDOW`, `TIMER-INFREQUENT`, `ACMEJSON-PERMS`, `DEAD-AUTH`, `OLD-CLIENT`. |
| `severity` | string | `error`, `warn` or `info`. |
| `client` | string | `certbot`, `acmesh`, `lego`, `caddy`, `traefik`, or `any` for a threshold found in a script or unit that is not tied to one client. |
| `file` | string | Path inside the audited root. |
| `line` | integer or null | 1-based line, or null when the finding is about a whole file. |
| `summary` | string | What is wrong, in one sentence. |
| `why` | string | Why it matters for the lifetimes tested. |
| `detail` | object | Machine-readable specifics. The keys depend on the kind and are listed below. |

## Detail keys by kind

| Kind | Keys |
| --- | --- |
| HOOK-MISSING, HOOK-NOT-EXECUTABLE | `field`, `role` (`pre`, `post`, `deploy`, `auth`), and for hooks named in a file or command `command` and `path`. |
| RENEW-WINDOW | `days` or `ratio` or `hours` (the setting), `target_days` (the lifetime it fails at). |
| HARDCODED-DAYS | `days`, `direction` (`since-issue`, `before-expiry` or `unknown`), and `target_days` when the direction is known. |
| TIMER-INFREQUENT | `schedule` (`timer`, `cron`, `caddy`, `timer-not-enabled` or `none`), and for a gap `gap_days` and `target_days`. |
| ACMEJSON-PERMS | `mode` (for example `644`), `resolver`, `config`. |
| DEAD-AUTH | `reason`: `syntax`, `missing-keys`, `no-renewalparams`, `no-authenticator`, `manual-without-hook`, `webroot-missing`, `autorenew-off`, `no-challenge` or `staging`. |
| OLD-CLIENT | `version`, `first_ari_version`, and for certbot `source` and `lineages`. |
