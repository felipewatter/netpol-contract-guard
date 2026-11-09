# JSON contract and snapshot schema (v1)

**Important:** this is a bounded JSON representation, not a full Kubernetes API object/YAML parser. Unknown fields are rejected intentionally. Native `NetworkPolicy` objects are restricted to the listed fields.

## Snapshot

Required root properties:

```json
{
  "apiVersion": "netpol.contractguard/v1",
  "namespaces": [ { "name": "web", "labels": {"team":"frontend"} } ],
  "pods": [ { "name": "frontend", "namespace": "web", "ip": "10.244.1.10", "labels": {"app":"frontend"}, "ports": [{"name":"http", "port":8080, "protocol":"TCP"}] } ],
  "policies": [ { "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {"name":"restrict","namespace":"web"}, "spec": {"podSelector":{},"policyTypes":["Ingress"],"ingress":[]} } ]
}
```

Namespaces have `name` (required) and `labels` (optional object). `kubernetes.io/metadata.name` is populated implicitly and must equal the namespace name if supplied. Pods have name/namespace/IP/labels and optional named container `ports`. Pod IPs and fully-qualified `namespace/name` identities must be unique. A Pod references an existing namespace. Policies must have a unique namespace/name and an existing namespace.

Policy specification accepted fields: `podSelector` (required in this strict subset), `policyTypes` (optional), `ingress`, `egress`. Ingress rules accept `from` and `ports`; egress rules accept `to` and `ports`. A peer accepts `podSelector`, `namespaceSelector` (individually or both), or `ipBlock` with `cidr` and optional `except`. Selectors support `matchLabels` and `matchExpressions` with `In`, `NotIn`, `Exists`, `DoesNotExist`. Port rules accept `protocol`, `port` (integer or name), and optional `endPort` (numeric only). This model rejects unsupported metadata (labels/annotations, status, UID, resourceVersion etc.) instead of silently ignoring them.

## Connectivity contracts

```json
{
  "apiVersion": "netpol.contractguard/v1",
  "contracts": [
    {
      "id":"NO_LATERAL_DB", "source":"web/frontend", "destination":"data/db",
      "protocol":"TCP", "port":5432, "expect":"deny", "severity":"critical", "reason":"deny direct DB access"
    }
  ]
}
```

Endpoints are `namespace/pod` or an external IP prefixed by `ip:` (example `ip:203.0.113.10`). One or both endpoints may be inventoried Pods, but both endpoints cannot be external IPs. Self-traffic probes are intentionally rejected. Protocol defaults to TCP; severity defaults to high; reason defaults to empty. Contract `id` values must be unique. The same contract file is used for `before` and `after` snapshots.

## Limits and validation errors

- JSON UTF-8 only, max 2,000,000 bytes per input file; duplicate JSON keys and non-finite floats are rejected.
- At most 100 namespaces, 300 Pods, 500 policies, 1,000 contracts; max 100 rules per direction, 100 peers per rule, 100 ports per rule and 30 selector requirements.
- IPs must be parseable, non-loopback, non-multicast and non-unspecified; CIDRs must use canonical subnet addresses with valid exceptions.
- CIDRs covering inventoried Pod IPs, even when used as external peers, are rejected as CNI-dependent ambiguity (unless excluded using a nested exception CIDR).
- Named ports are resolved only against inventoried destination Pod ports. They cannot be modeled on an external IP destination.
- Contract protocol is TCP/UDP/SCTP and destination port is 1–65535. Unknown keys, unsupported operators or duplicates cause exit code 3.
- When comparing policies, namespace labels, Pods, Pod labels, IPs and named ports must be byte-for-byte equivalent in parsed objects. Change these in a separate migration and generate a new baseline.

## Reading diagnostics

`report.results[]`: `id`, `source`, `destination`, `protocol`, `port`, `expected`, `actual`, `pass`, `severity`, `reason`, `egress`, `ingress`. The latter two include `isolated`, `policies` (matched allow policies) and `reason`. Comparison additionally includes `before`, `baselinePass` and `drift` (`new-exposure`, `connectivity-loss`, `unchanged`). The report summary includes count of violations and modeled changes. The overall gate result is determined **only by contract violations** at or above the selected severity threshold; a drift in an unspecified connection cannot be detected.

## Data minimization

Export only the labels and endpoint data necessary for the contracts; never include Secret resources, service account tokens, kubeconfigs, internal credentials, identifying human data or proprietary service topology in a public Git repository.
