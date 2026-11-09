# Threat model and safe use

## Assets

- Confidentiality and integrity of infrastructure configuration exported for review.
- Deterministic evaluation of allow/deny contracts and auditable change decisions.
- Integrity of the release SHA, evidence artifacts and checksums.

## Trust assumptions

- A human controls which Pods, namespaces and connectivity contracts form the bounded snapshot.
- Pod/namespace inventory values are accurate for the **same point in time**. No Kubernetes API or CNI state is consulted.
- The environment actually runs a CNI implementing Kubernetes NetworkPolicy for affected Pods; otherwise a modeled `deny` may be an actual `allow`.
- CI runners are trusted; a compromised runner or GitHub organization token can compromise results.

## Attacker-controlled surfaces

- Malformed JSON inputs, duplicates, wrong types, CIDR and label selector bombs, artificial connections, Unicode strings.
- Untrusted PRs that modify policies, synthetic fixtures, code or workflows.
- Output paths potentially pointing to symlinks or nonexistent/readonly directories.
- Release triggers, stale workflows and re-publication of previously used tags.

## Controls

| Threat | Mitigation |
| --- | --- |
| JSON shadowing / duplicate keys | duplicate-key exception while decoding |
| Memory exhaustion | 2MB max file; hard caps on namespaces, Pods, contracts, policies, rules and peers |
| Misleading policy interpretation | reject unsupported fields and conflicting peers; model native policy selection and union |
| Pod-IP `ipBlock` ambiguity | fail closed on CIDRs containing inventoried Pod addresses |
| Tampered inventory during a policy delta | require exact same Pod and namespace inventory in both snapshots |
| Unrestricted external-to-external probes | reject; no policy endpoint exists to enforce these |
| Unexpected file overwrite through symlink | reject symlink output path; write atomically to parent directory |
| PR-controlled publishing | release requires successful push CI on `main` and matching repository identity |
| Stale CI publish | compare successful CI SHA to both checked-out commit and live `main` ref |
| Dependency supply-chain drift | pinned checkout/setup-python SHAs; no application runtime dependencies |
| Release tag rebind | do not overwrite existing releases; reject pre-existing unrelated tag |
| Sensitive fixtures in public source | fictional examples only; never include real IP topology, kubeconfig, secrets |

## Non-goals / risk acceptance

- No admission controller, enforcement daemon, active scanner, VPN, firewall or sidecar.
- Does not model NAT/Service address translation, node-to-Pod exceptions, host-network routing, NetworkPolicy interactions with CNI-specific APIs, mesh proxies, ICMP, SCTP availability, endPort availability, DNS policy, app layer or StatefulSet readiness.
- Does not enumerate flows absent from explicit contracts. Missing a dangerous contract can produce a green report while actual connectivity remains dangerous.
- Does not validate how policy changes affect **existing established connections**; platform-specific behavior is outside Kubernetes NetworkPolicy model guarantees.
- `ipBlock` is conditional on CNI behavior, NAT order and IP recognition; overlapping Pod IPs are rejected, but that cannot remove all platform-dependent ambiguity.
- No assurance that DNS names resolve or that services listen on the declared ports.
- Automated outcomes do not substitute change tickets, staging verification, vulnerability management, security review or rollback plans.

## Reporting

Please report vulnerabilities privately via the GitHub Security Advisory feature when enabled, or by opening an issue that **omits exploit details, access tokens, production topology and personal information** and requests a secure contact channel. See `SECURITY.md`.
