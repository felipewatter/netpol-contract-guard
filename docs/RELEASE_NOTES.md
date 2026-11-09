# NetPol ContractGuard v0.1.0 — Initial public release

A new offline Kubernetes NetworkPolicy contract testing CLI with explicitly scoped TCP/UDP/SCTP semantics.

- Native `networking.k8s.io/v1` policy evaluation for inventoried Pods and external IP contract endpoints.
- Correctly separates ingress and egress isolation; additive policy union, Kubernetes label/namespace selectors, CIDR/except, named ports and numeric `endPort`.
- Independent version-controlled allow/deny contracts with severity, rationale and deterministic diff classification of `new-exposure` or `connectivity-loss`.
- Text/JSON/SARIF 2.1.0 reporting with clear CI gate exits (`0`, `2`, `3`).
- Bounded input validation, strict JSON handling, Pod-IP `ipBlock` ambiguity refusal, atomic output and adversarial regression tests.
- 9-platform CI matrix (Ubuntu/Windows/macOS; Python 3.11, 3.12, 3.13), SHA-pinned GitHub Actions and immutable release after green CI on exact `main` SHA.
- Reproducible source ZIP, SHA-256 manifest/checksums and Python Wheel. Extensive PT-BR and EN documentation, security policy, threat model, tests and fictional example datasets.

**No live cluster validation:** Does not talk to Kubernetes APIs, enforce policies, model CNI/Service/NAT/mesh behavior or prove full reachability security. This is contract-focused, scoped static modeling; manual review and operational tests remain mandatory.
