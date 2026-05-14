# Security

## Supported versions

Security fixes are applied to the latest release on the default branch. Use tagged releases for production deployments.

## Reporting a vulnerability

Please report sensitive issues privately so they can be addressed before public disclosure. Include reproduction steps, affected component (web UI, CLI, GitHub integration), and severity assessment if possible.

## Deployment hardening

- Change default HTTP Basic credentials (`ADMIN_USERNAME`, `ADMIN_PASSWORD`) and use a long random `SESSION_SECRET_KEY`.
- Run behind TLS (see `nginx.conf` / your ingress) so Basic authentication and GitHub OAuth tokens are not sent in cleartext.
- Restrict network access to the scanner if it is used for internal repositories; it clones and unpacks user-supplied code.
- Optional AI features require `GROQ_API_KEY` or `OPENAI_API_KEY`; treat these as secrets.

## Demo vulnerable code

The file `examples/bad_patterns/insecure_sample.py` contains **intentionally insecure** patterns for demonstrations and static analysis testing. It is not part of the runtime application.
