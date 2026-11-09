# Security policy

## Supported versions

| Version | Support |
| --- | --- |
| 0.1.x | Supported when published as the latest release |
| Earlier | Not supported |

## Coordinated vulnerability disclosure

Use GitHub **Report a vulnerability** / private Security Advisories for this repository if available. If the option is not available, create a minimal public issue **without proof-of-concept exploit payloads, credentials, private IP topologies or sensitive data** and request a secure contact channel. Provide version, impact, non-sensitive reproduction, boundary conditions and the security property violated.

Please allow reasonable remediation time before publication; security-impacting defects take precedence over regular feature work. We do not promise a fixed response SLA for this volunteer project.

## Usage warning

This project analyzes **sanitized, offline JSON** and must not be trusted as evidence that a running cluster actually enforces any policy. Never connect it directly to live Kubernetes infrastructure or use it as an autonomous production deployment approver. A green security gate is limited to the declared contract probes, supported semantics and accuracy of input inventory.
