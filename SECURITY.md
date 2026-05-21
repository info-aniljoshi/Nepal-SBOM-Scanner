# Security Policy

## Supported Versions

We only provide security updates for the current major version of Nepal SBOM Scanner.

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take the security of Nepal SBOM Scanner seriously. If you believe you have found a security vulnerability, please report it to us by following these steps:

1. **Do not open a public issue.**
2. Send an email to **security@nepalsecurity.org** (placeholder) or use the GitHub Private Vulnerability Reporting feature.
3. Include as much detail as possible, including steps to reproduce the issue.

We will acknowledge your report within 48 hours and provide a timeline for a fix.

## Security Best Practices for Operators

- **Environment Variables**: Never commit your `.env` file.
- **Admin Password**: Change the default `ADMIN_PASSWORD` immediately after deployment.
- **TLS**: Always run this application behind a reverse proxy (like Nginx or Caddy) with TLS enabled.
- **Database**: Ensure the `nepal_sbom.db` file has restricted filesystem permissions.
