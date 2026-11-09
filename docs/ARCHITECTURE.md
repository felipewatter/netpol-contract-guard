# Technical architecture

## Execution boundary

1. An engineer exports a sanitized namespace/Pod inventory and selects native NetworkPolicy fields into a version-controlled JSON file.
2. Independent, version-controlled connectivity contracts specify *exact* test vectors: source, destination, protocol, port, expected behavior and severity.
3. The bounded parser rejects oversized files, duplicate JSON keys, unknown fields, duplicate object identities, invalid selectors, malformed CIDR ranges and ill-typed ports.
4. The evaluator builds the set of NetworkPolicies selecting each Pod. `Ingress` and `Egress` are independent. Any matching allow rule from a selecting policy permits that direction. If no policy selects the Pod for that direction, the direction is allowed by default.
5. One contract passes only when its expected `allow` or `deny` equals the simulated final result. A flow is allowed only if both source egress and destination ingress pass.
6. Optional `compare` separately evaluates baseline and candidate **with identical inventories and contracts**, returning deterministic classification of modeled behavior changes.
7. The severity threshold converts contract violations into CI failure. Text, JSON and SARIF are generated without network activity or third-party libraries.

## Module layout

```text
src/netpol_contract_guard/
  model.py    strict schema validation, bounded JSON, identity and CIDR handling
  engine.py   NetworkPolicy selection, peer/port matching, audit and delta reports
  cli.py      command-line interface, explicit exit codes, atomic writes
  __main__.py python -m entrypoint
scripts/
  build_release.py       reproducible sources / manifest / checksums
  generate_fixtures.py  deterministic fictitious example data
examples/
  baseline.json         safe example policies
  candidate-risky.json policy added that creates lateral exposure
  contracts.json        invariant connectivity requirements
tests/
  test_semantics.py     evidence of independent ingress/egress semantics
  test_validation.py    fail-closed malformed/ambiguous input cases
  test_cli.py           subprocess behavior, outputs and error codes
  test_release.py       reproducibility and completeness of distributed archives
.github/workflows/
  ci.yml                3 OS × 3 Python versions and regression gate
  release.yml           SHA-bound immutable release after successful push CI
```

## Determinism and trust boundaries

Inputs are data, not commands. No YAML document merging, templating, `eval`, remote fetch, subprocess execution in the engine, shell interpolations or live-cluster lookups. JSON decoding uses `object_pairs_hook` to reject duplicate keys and a 2MB file-size cap. The release builder includes an explicit list of source paths and normalizes ZIP metadata; SHA256SUMS and a per-source-file manifest enable independent integrity checking. Local outputs use an atomic replace and reject symbolic-link destinations.

GitHub Actions checks out the exact SHA from a successful `main` push. Untrusted pull-request workflows **cannot trigger publishing**, and stale CI SHAs cannot publish over a newer `main`. A release tag is never moved to a different commit. The semantic version comes from `pyproject.toml`; all release tests use the imported package version rather than hard-coded filenames.

## Internal data flow

```text
snapshot.json ── validate ─┐
                           ├── evaluate every contract ── gate ── text / JSON / SARIF
contracts.json ─ validate ─┘                 │
                                            └── explain ingress and egress
baseline.json ── validate ─┐
candidate.json ─ validate ─┼── enforce same inventory ── compare outcomes ── drift labels
contracts.json ─ validate ─┘
```

## Known semantic tradeoffs

This implementation optimizes for traceable **contract assertions**, not complete reachability. It deliberately does not expand arbitrary port ranges or generate all possible endpoint/port combinations. Only declared probes are evaluated. It rejects ambiguous Pod-IP `ipBlock` overlap, invalid or unsupported metadata/fields, self traffic, external-to-external flows, unsupported protocols and changed inventory comparisons. No claims are made about whether a CNI is installed or enforces policies; this is a policy model only.
