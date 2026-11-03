# Security

## Reporting a vulnerability

Please use GitHub private vulnerability reporting. Open the Security tab of this repository and choose "Report a vulnerability". The report stays private until a fix is out. Don't open a public issue for something exploitable.

Say what you ran, what you expected and what happened. A small directory tree that reproduces it helps most. Take out real hostnames and anything that looks like a secret first.

## What is in scope

acme-audit reads configuration files and writes nothing. The areas worth a look:

- Anything that makes it write, rename or delete a file under the root it audits, or run a program, or open a network connection.
- Path handling under `--root`, including symlinks that point outside it. A link to `/etc/shadow` inside an audited tree should be resolved inside the root, not on the host.
- Output that prints the contents of a file it should only be inspecting. It prints paths, line numbers and the hook commands it finds. It should never print a token or a private key.
- A crafted config that makes it hang or use a lot of memory.

## Supported versions

Only the latest release gets fixes. The project is small and has no runtime dependencies.
