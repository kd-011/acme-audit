# Contributing

Bug reports, fixes, new checks and updates to the schedule data are all welcome.

## Ground rules

- Node 22, ES modules, no npm dependencies. Use `node:` built-ins.
- acme-audit only reads. It never runs a client, never opens a network connection and never writes. Only `src/demo-tree.mjs` may write, and only inside its own temp dir. A change that weakens that needs a test showing it does not.
- No lifetime, date or threshold is typed into the code. It goes in `data/schedule.json` with a source URL and the date you read it. If you cannot point at a page, leave it out.
- Tests build real fixtures: a real certbot renewal file under a temp root, a real Caddyfile, a file with the mode a real machine would have. Reproduce the layout from the client's own documentation or source.

## Running the tests

```sh
node --test                         # everything, a few seconds
node --test test/certbot.test.mjs   # one file while you work
```

## Sign-off (DCO)

There is no CLA. Certify the [Developer Certificate of Origin](https://developercertificate.org/) by signing off each commit:

```sh
git commit -s -m "Read renew_before_expiry in months"
```

That adds a `Signed-off-by:` line with your git name and email.

## Dependency updates and CI

Dependabot proposes GitHub Actions updates weekly. Patch and minor updates, and any update to an action from the `actions/` organisation, merge on their own once the required checks pass. Other major updates wait for a person. CI runs `node --test` on Node 22 and 24, and once a week so the badge shows the current state of `main`.

A weekly job checks the links in the README and runs `dossier-scribe check` against the dossier in `dossiers/`. If a cited file changed, it opens one issue. To clear it, re-read the cited files, fix any claims that are no longer true, run `dossier-scribe pin` and commit the dossier and lock.

## Updating the schedule

When Let's Encrypt or a client changes something, edit `data/schedule.json`: the value, its source entry, and the `checked` date. `node --test` fails if a source has no URL or date, or if a value cites a source that is not listed.

## Pull requests

Keep them small, add or update a test, and update the README when behaviour changes. Plain imperative commit messages are fine.
