# NetPol ContractGuard (English)

**An offline, deterministic Kubernetes NetworkPolicy connectivity-contract gate.** Written in Python 3.11+, with no required runtime dependencies.

[![CI](https://github.com/felipewatter/netpol-contract-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/felipewatter/netpol-contract-guard/actions/workflows/ci.yml)
[![MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Português:** [README.md](README.md). Author: [Felipe Watter](https://github.com/felipewatter).

## Purpose

Prevent explicit connectivity regressions from being silently introduced by Kubernetes NetworkPolicy changes. A version-controlled contract describes a source endpoint, destination endpoint, protocol, destination port, expected `allow`/`deny`, severity and rationale. The tool evaluates that contract on a validated offline snapshot of namespaces, Pod inventory and native Kubernetes `NetworkPolicy` JSON objects.

A `compare` operation runs the **same contracts and inventory** against a baseline and candidate set of policies, distinguishing `new-exposure`, `connectivity-loss` and `unchanged`. It reports the contributing ingress and egress evaluation separately. This is a sampled/contract-specific model, **not a full cluster reachability proof**. More broadly applicable semantic analysis is available from [NP-Guard](https://github.com/np-guard/network-config-analyzer); this implementation is independent.

## Install and run

```bash
git clone https://github.com/felipewatter/netpol-contract-guard.git
cd netpol-contract-guard
python -m pip install --no-deps -e .

netpol-contract-guard audit --snapshot examples/baseline.json --contracts examples/contracts.json
netpol-contract-guard compare --before examples/baseline.json --after examples/candidate-risky.json --contracts examples/contracts.json
```

The clean audit returns **0**. The risky sample detects lateral access to a database and returns **2**. Invalid or ambiguous input returns **3**. Optionally set `--fail-on low|medium|high|critical|none` and `--format json --output report.json --sarif findings.sarif`.

## Supported semantics

- Independent source egress / destination ingress isolation with additive NetworkPolicy union.
- `podSelector`, `namespaceSelector`, paired selectors, `matchLabels`, `In`, `NotIn`, `Exists`, `DoesNotExist`.
- IPv4/IPv6 `ipBlock` with nested `except` ranges; ambiguous Pod-IP overlap is rejected.
- Numeric, named destination Pod ports and `endPort` ranges, with TCP, UDP and SCTP.
- Empty ingress/egress rule lists vs empty peer/port selections.
- Strict 2MB JSON bound, object validation, duplicate-key/duplicate-entity rejection, consistent snapshot inventory and atomic output writes.
- Structured JSON and SARIF 2.1.0 with rule IDs, deterministic findings and severity-based CI gate.

## Security model and limitations

There is **no** network client, kubeconfig parsing, authentication, SSH, command execution, cluster mutation or API token use. The files are intentionally strict JSON fixtures, not raw Kubernetes YAML or unrestricted API objects. This is a model of selected TCP/UDP/SCTP connections, not runtime CNI enforcement. Pod and namespace labels, selected peer scope, port resolution and IPBlocks are deterministic within this explicit subset. **Services, NAT, host-network traffic, nodes, DNS, ICMP, CNI extensions, CRDs, mesh rules, established flows, administrative policies and clusters without NetworkPolicy enforcement are out of scope.** IPBlocks covering Pod IPs are rejected due to CNI-dependent semantics; external-to-external and self-Pod traffic are rejected.

Do not treat a green report as proof of cluster security. Production deployment requires human review and real network checks. See [Threat model](docs/THREAT_MODEL.md), [Architecture](docs/ARCHITECTURE.md), [Format](docs/FORMAT.md) and [Security policy](SECURITY.md).

## CI and releases

`.github/workflows/ci.yml` tests on Ubuntu, Windows and macOS, each with Python 3.11–3.13 (9 combinations). The release workflow runs only after a green `main` push CI, pins the successful SHA, refuses to publish if the branch advanced, tests again and creates immutable source ZIP, Python Wheel, manifest and SHA256SUMS. Third-party Actions use full immutable commit SHAs with no persisted checkout credentials. Existing tags are not rebound and existing release assets are not overwritten.

## Documentation

The repository contains a detailed Portuguese README, English README, tests, synthetic scenarios, SARIF export, threat model, changelog, release notes, MIT license, responsible disclosure policy and contribution guide. Kubernetes concepts and API semantics: [official NetworkPolicy documentation](https://kubernetes.io/docs/concepts/services-networking/network-policies/) and [reference](https://kubernetes.io/docs/reference/kubernetes-api/networking/network-policy-v1/).
