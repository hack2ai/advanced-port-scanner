# Security Policy

## Scope

Advanced Port Scanner is intended for authorized defensive network discovery, administration, troubleshooting, and controlled security labs.

## Safe use

Only scan systems and networks you own or have explicit permission to assess. The project is intentionally scoped away from credential attacks, exploitation, stealth, and evasion.

## Reporting a vulnerability

Please do not disclose exploitable details in a public issue. Report security concerns privately to the repository maintainers through the security contact configured for the project.

Include:

- affected version or commit
- affected component
- clear reproduction steps
- security impact
- any practical mitigation

Allow maintainers reasonable time to investigate before public disclosure.

## Deployment guidance

Before exposing the Flask API to untrusted users, deploy it behind authentication, TLS, network controls, and appropriate rate limiting. Review container privileges and persistent-data permissions for your environment.
