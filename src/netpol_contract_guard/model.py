"""Strict, size-bounded ingestion of trusted-format but untrusted-content JSON snapshots."""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_BYTES = 2_000_000
MAX_NAMESPACE = 100
MAX_PODS = 300
MAX_POLICIES = 500
MAX_CONTRACTS = 1000
MAX_RULES = 100
MAX_PEERS = 100
MAX_PORTS = 100
MAX_SELECTOR_PARTS = 30
MAX_LABELS = 100
ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,125}$")
SEVERITIES = ("low", "medium", "high", "critical")
PROTOCOLS = ("TCP", "UDP", "SCTP")

class InputError(ValueError):
    """Untrusted, malformed or unsupported input; exit fail-closed."""


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise InputError(f"duplicate JSON key: {key}")
        out[key] = value
    return out


def read_json(path: str | Path) -> Any:
    source = Path(path)
    if source.is_symlink() or not source.is_file():
        raise InputError(f"not a regular JSON file: {source}")
    if source.stat().st_size > MAX_BYTES:
        raise InputError("JSON file exceeds 2MB bound")
    try:
        with source.open("rb") as file:
            raw = file.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise InputError("JSON file exceeds 2MB bound")
        return json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates,
                          parse_constant=lambda c: (_ for _ in ()).throw(InputError(f"non-finite number: {c}")))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise InputError(f"invalid JSON: {exc}") from exc
    except OSError as exc:
        raise InputError(f"cannot read input: {exc}") from exc


def obj(value: Any, fields: set[str], context: str, required: set[str] | None = None) -> dict:
    if not isinstance(value, dict):
        raise InputError(f"{context}: expected object")
    unexpected = set(value) - fields
    if unexpected:
        raise InputError(f"{context}: unsupported fields {', '.join(sorted(unexpected))}")
    missing = (required or set()) - set(value)
    if missing:
        raise InputError(f"{context}: missing {', '.join(sorted(missing))}")
    return value


def seq(value: Any, maximum: int, context: str) -> list:
    if not isinstance(value, list) or len(value) > maximum:
        raise InputError(f"{context}: expected array with at most {maximum} entries")
    return value


def ident(value: Any, context: str) -> str:
    if not isinstance(value, str) or not ID_RE.fullmatch(value):
        raise InputError(f"{context}: invalid identifier")
    return value


def labels(value: Any, context: str) -> dict[str, str]:
    if not isinstance(value, dict) or len(value) > MAX_LABELS:
        raise InputError(f"{context}: labels must be a bounded object")
    for key, v in value.items():
        # K8s qualified keys may use '/' and the label values may be empty.
        if not isinstance(key, str) or not (1 <= len(key) <= 253) or not re.fullmatch(r"[A-Za-z0-9./_-]+", key):
            raise InputError(f"{context}: invalid label key")
        if not isinstance(v, str) or len(v) > 63:
            raise InputError(f"{context}: invalid label value")
    return value


def selector(value: Any, context: str) -> dict:
    v = obj(value, {"matchLabels", "matchExpressions"}, context)
    labels(v.get("matchLabels", {}), context + ".matchLabels")
    for entry in seq(v.get("matchExpressions", []), MAX_SELECTOR_PARTS, context + ".matchExpressions"):
        x = obj(entry, {"key", "operator", "values"}, context + ".expression", {"key", "operator"})
        if not isinstance(x["key"], str) or not re.fullmatch(r"[A-Za-z0-9./_-]{1,253}", x["key"]):
            raise InputError(f"{context}: invalid expression key")
        if x["operator"] not in ("In", "NotIn", "Exists", "DoesNotExist"):
            raise InputError(f"{context}: invalid selector operator")
        values = seq(x.get("values", []), MAX_SELECTOR_PARTS, context + ".values")
        if not all(isinstance(i, str) and len(i) <= 63 for i in values):
            raise InputError(f"{context}: invalid selector values")
        if x["operator"] in ("In", "NotIn") and not values:
            raise InputError(f"{context}: In/NotIn needs values")
        if x["operator"] in ("Exists", "DoesNotExist") and values:
            raise InputError(f"{context}: Exists/DoesNotExist forbids values")
    return v


def port_number(value: Any, context: str) -> int:
    if type(value) is not int or not 1 <= value <= 65535:
        raise InputError(f"{context}: expected TCP/UDP/SCTP port 1..65535")
    return value


def ip(value: Any, context: str) -> str:
    if not isinstance(value, str):
        raise InputError(f"{context}: invalid IP")
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as exc:
        raise InputError(f"{context}: invalid IP") from exc
    if parsed.is_multicast or parsed.is_unspecified or parsed.is_loopback:
        raise InputError(f"{context}: unsupported IP address range")
    return str(parsed)


def peer(value: Any, context: str) -> dict:
    x = obj(value, {"podSelector", "namespaceSelector", "ipBlock"}, context)
    if "ipBlock" in x:
        if len(x) != 1:
            raise InputError(f"{context}: ipBlock cannot be combined with selectors")
        block = obj(x["ipBlock"], {"cidr", "except"}, context + ".ipBlock", {"cidr"})
        exclusions = seq(block.get("except", []), MAX_PEERS, context + ".except")
        if not isinstance(block["cidr"], str) or any(not isinstance(e, str) for e in exclusions):
            raise InputError(f"{context}: CIDR and exclusions must be strings")
        try:
            net = ipaddress.ip_network(block["cidr"], strict=True)
            for item in exclusions:
                excluded = ipaddress.ip_network(item, strict=True)
                if not excluded.subnet_of(net):
                    raise InputError(f"{context}: exception must be a subnet of CIDR")
        except (ValueError, TypeError, KeyError) as exc:
            raise InputError(f"{context}: invalid CIDR") from exc
    if "podSelector" in x:
        selector(x["podSelector"], context + ".podSelector")
    if "namespaceSelector" in x:
        selector(x["namespaceSelector"], context + ".namespaceSelector")
    return x


def policy_port(value: Any, context: str) -> dict:
    x = obj(value, {"protocol", "port", "endPort"}, context)
    if x.get("protocol", "TCP") not in PROTOCOLS:
        raise InputError(f"{context}: unsupported protocol")
    if "port" in x:
        if isinstance(x["port"], str):
            ident(x["port"], context + ".port")
        else:
            port_number(x["port"], context + ".port")
    if "endPort" in x:
        port_number(x["endPort"], context + ".endPort")
        if type(x.get("port")) is not int or x["endPort"] < x["port"]:
            raise InputError(f"{context}: endPort requires a numeric start <= endPort")
    return x


def policy(value: Any, context: str) -> dict:
    x = obj(value, {"apiVersion", "kind", "metadata", "spec"}, context,
            {"apiVersion", "kind", "metadata", "spec"})
    if x["apiVersion"] != "networking.k8s.io/v1" or x["kind"] != "NetworkPolicy":
        raise InputError(f"{context}: only native networking.k8s.io/v1 NetworkPolicy is supported")
    meta = obj(x["metadata"], {"name", "namespace"}, context + ".metadata", {"name", "namespace"})
    ident(meta["name"], context + ".metadata.name")
    ident(meta["namespace"], context + ".metadata.namespace")
    spec = obj(x["spec"], {"podSelector", "policyTypes", "ingress", "egress"}, context + ".spec", {"podSelector"})
    selector(spec["podSelector"], context + ".spec.podSelector")
    types = seq(spec.get("policyTypes", []), 2, context + ".spec.policyTypes")
    if any(not isinstance(t, str) or t not in ("Ingress", "Egress") for t in types) or len(set(types)) != len(types):
        raise InputError(f"{context}: invalid policyTypes")
    if "policyTypes" in spec and not types:
        raise InputError(f"{context}: policyTypes cannot be empty")
    for direction in ("ingress", "egress"):
        for ri, rule in enumerate(seq(spec.get(direction, []), MAX_RULES, context + "." + direction)):
            rule = obj(rule, {"from", "to", "ports"}, f"{context}.{direction}[{ri}]")
            peer_key = "from" if direction == "ingress" else "to"
            other_key = "to" if direction == "ingress" else "from"
            if other_key in rule:
                raise InputError(f"{context}: {other_key} not valid on {direction}")
            for i, p in enumerate(seq(rule.get(peer_key, []), MAX_PEERS, context + ".peers")):
                peer(p, f"{context}.{direction}[{ri}].{peer_key}[{i}]")
            for i, p in enumerate(seq(rule.get("ports", []), MAX_PORTS, context + ".ports")):
                policy_port(p, f"{context}.{direction}[{ri}].ports[{i}]")
    return x


@dataclass(frozen=True)
class Snapshot:
    namespaces: dict[str, dict[str, str]]
    pods: dict[str, dict]
    policies: tuple[dict, ...]


def parse_snapshot(value: Any) -> Snapshot:
    x = obj(value, {"apiVersion", "namespaces", "pods", "policies"}, "snapshot",
            {"apiVersion", "namespaces", "pods", "policies"})
    if x["apiVersion"] != "netpol.contractguard/v1":
        raise InputError("snapshot: unsupported apiVersion")
    namespaces = {}
    for idx, item in enumerate(seq(x["namespaces"], MAX_NAMESPACE, "namespaces")):
        v = obj(item, {"name", "labels"}, f"namespaces[{idx}]", {"name"})
        name = ident(v["name"], "namespace name")
        if name in namespaces:
            raise InputError(f"duplicate namespace: {name}")
        nslabels = dict(labels(v.get("labels", {}), "namespace labels"))
        # Kubernetes exposes the immutable namespace-name label.
        if "kubernetes.io/metadata.name" in nslabels and nslabels["kubernetes.io/metadata.name"] != name:
            raise InputError(f"namespace {name}: immutable metadata.name label mismatch")
        nslabels["kubernetes.io/metadata.name"] = name
        namespaces[name] = nslabels
    pods = {}
    seen_ip = set()
    for i, item in enumerate(seq(x["pods"], MAX_PODS, "pods")):
        v = obj(item, {"name", "namespace", "labels", "ip", "ports"}, f"pods[{i}]",
                {"name", "namespace", "labels", "ip"})
        name = ident(v["name"], "pod name")
        ns = ident(v["namespace"], "pod namespace")
        if ns not in namespaces:
            raise InputError(f"pod {name}: namespace {ns} not defined")
        address = ip(v["ip"], "pod IP")
        key = ns + "/" + name
        if key in pods or address in seen_ip:
            raise InputError("duplicate pod name or IP")
        seen_ip.add(address)
        labels(v.get("labels", {}), "pod labels")
        ports = seq(v.get("ports", []), MAX_PORTS, "pod ports")
        seen_named = set()
        for j, p in enumerate(ports):
            entry = obj(p, {"name", "port", "protocol"}, f"pod ports[{j}]", {"name", "port"})
            ident(entry["name"], "named port")
            port_number(entry["port"], "port")
            if entry.get("protocol", "TCP") not in PROTOCOLS:
                raise InputError("unsupported named port protocol")
            portkey = (entry["name"], entry.get("protocol", "TCP"))
            if portkey in seen_named:
                raise InputError("duplicate named container port")
            seen_named.add(portkey)
        pods[key] = v
    policies = []
    unique = set()
    for i, p in enumerate(seq(x["policies"], MAX_POLICIES, "policies")):
        validated = policy(p, f"policies[{i}]")
        meta = validated["metadata"]
        key = (meta["namespace"], meta["name"])
        if key in unique:
            raise InputError("duplicate policy")
        if key[0] not in namespaces:
            raise InputError(f"policy namespace {key[0]} does not exist")
        unique.add(key)
        policies.append(validated)
    return Snapshot(namespaces, pods, tuple(policies))


@dataclass(frozen=True)
class Contract:
    id: str
    source: str
    destination: str
    protocol: str
    port: int
    expect: str
    severity: str
    reason: str


def parse_contracts(value: Any, snapshot: Snapshot) -> tuple[Contract, ...]:
    root = obj(value, {"apiVersion", "contracts"}, "contract root", {"apiVersion", "contracts"})
    if root["apiVersion"] != "netpol.contractguard/v1":
        raise InputError("contract root: unsupported apiVersion")
    seen = set()
    entries = []
    pod_ips = {p["ip"] for p in snapshot.pods.values()}
    for i, entry in enumerate(seq(root["contracts"], MAX_CONTRACTS, "contracts")):
        v = obj(entry, {"id", "source", "destination", "protocol", "port", "expect", "severity", "reason"},
                f"contracts[{i}]", {"id", "source", "destination", "port", "expect"})
        key = ident(v["id"], "contract id")
        if key in seen:
            raise InputError("duplicate contract ID")
        seen.add(key)
        a = v["source"]; b = v["destination"]
        for endpoint in (a, b):
            if not isinstance(endpoint, str):
                raise InputError("endpoint must be a string")
            if endpoint.startswith("ip:"):
                addr = ip(endpoint[3:], "external IP")
                if addr in pod_ips:
                    raise InputError("IP endpoint aliases an inventoried Pod")
            elif endpoint not in snapshot.pods:
                raise InputError(f"unknown pod endpoint {endpoint}")
        if a == b:
            raise InputError("self-traffic is excluded from this conservative offline model")
        if a.startswith("ip:") and b.startswith("ip:"):
            raise InputError("external-to-external flows cannot be evaluated without Pod policy endpoints")
        protocol = v.get("protocol", "TCP")
        if protocol not in PROTOCOLS:
            raise InputError("unsupported contract protocol")
        port_number(v["port"], "contract port")
        if v["expect"] not in ("allow", "deny"):
            raise InputError("contract expect must be allow or deny")
        severity = v.get("severity", "high")
        if severity not in SEVERITIES:
            raise InputError("unsupported severity")
        reason = v.get("reason", "")
        if not isinstance(reason, str) or len(reason) > 500:
            raise InputError("contract reason invalid")
        entries.append(Contract(key, a, b, protocol, v["port"], v["expect"], severity, reason))
    return tuple(entries)


def same_inventory(before: Snapshot, after: Snapshot) -> None:
    # Changed labels / pod IPs alter the meaning of probes. Reject rather than mislabel drift.
    if before.namespaces != after.namespaces or before.pods != after.pods:
        raise InputError("comparison requires identical namespace and Pod inventories (labels, IPs and named ports)")
