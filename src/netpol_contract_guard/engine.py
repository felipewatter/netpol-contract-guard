"""Deterministic connectivity evaluator implementing a deliberately bounded K8s subset."""
from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import asdict
from typing import Any

from .model import Contract, InputError, Snapshot, SEVERITIES


def selected(sel: dict, labels: dict[str, str]) -> bool:
    if any(labels.get(k) != v for k, v in sel.get("matchLabels", {}).items()):
        return False
    for exp in sel.get("matchExpressions", []):
        key, op = exp["key"], exp["operator"]
        present = key in labels
        vals = exp.get("values", [])
        if op == "In" and (not present or labels[key] not in vals):
            return False
        if op == "NotIn" and (present and labels[key] in vals):
            return False
        if op == "Exists" and not present:
            return False
        if op == "DoesNotExist" and present:
            return False
    return True


def policy_types(spec: dict) -> set[str]:
    if "policyTypes" in spec:
        return set(spec["policyTypes"])
    return {"Ingress", "Egress"} if spec.get("egress") else {"Ingress"}


def pod_for(snapshot: Snapshot, endpoint: str) -> dict | None:
    return snapshot.pods.get(endpoint)


def peer_matches(snapshot: Snapshot, policy: dict, peer: dict, endpoint: str) -> bool:
    pod = pod_for(snapshot, endpoint)
    if "ipBlock" in peer:
        if pod is not None:
            # CNI-dependent Pod-IP interpretation. Prohibit this ambiguity at parse stage.
            return False
        addr = ipaddress.ip_address(endpoint[3:])
        block = peer["ipBlock"]
        network = ipaddress.ip_network(block["cidr"])
        return addr in network and not any(addr in ipaddress.ip_network(ex) for ex in block.get("except", []))
    if pod is None:
        return False
    if "namespaceSelector" in peer:
        if not selected(peer["namespaceSelector"], snapshot.namespaces[pod["namespace"]]):
            return False
    elif pod["namespace"] != policy["metadata"]["namespace"]:
        # If neither selector is present, {} matches ALL peers, including external IPs.
        if peer:
            return False
    if "podSelector" in peer and not selected(peer["podSelector"], pod.get("labels", {})):
        return False
    return True


def matching_port(port_rule: dict, contract: Contract, destination: dict | None) -> bool:
    if port_rule.get("protocol", "TCP") != contract.protocol:
        return False
    configured = port_rule.get("port")
    if configured is None:
        return True
    if isinstance(configured, str):
        if destination is None:
            raise InputError("named port cannot be resolved for an external IP destination")
        return any(p["name"] == configured and p["port"] == contract.port and
                   p.get("protocol", "TCP") == contract.protocol for p in destination.get("ports", []))
    return configured <= contract.port <= port_rule.get("endPort", configured)


def rule_matches(snapshot: Snapshot, policy: dict, rule: dict, contract: Contract, direction: str) -> bool:
    peer_key = "from" if direction == "Ingress" else "to"
    peers = rule.get(peer_key, [])
    endpoint = contract.source if direction == "Ingress" else contract.destination
    if peers and not any(not p or peer_matches(snapshot, policy, p, endpoint) for p in peers):
        return False
    destination = pod_for(snapshot, contract.destination)
    ports = rule.get("ports", [])
    return not ports or any(matching_port(p, contract, destination) for p in ports)


def directional(snapshot: Snapshot, contract: Contract, direction: str) -> tuple[bool, dict]:
    endpoint = contract.destination if direction == "Ingress" else contract.source
    pod = pod_for(snapshot, endpoint)
    if pod is None:
        return True, {"direction": direction, "isolated": False, "policies": [], "reason": "external endpoint"}
    policies = [p for p in snapshot.policies
                if p["metadata"]["namespace"] == pod["namespace"]
                and direction in policy_types(p["spec"])
                and selected(p["spec"]["podSelector"], pod.get("labels", {}))]
    if not policies:
        return True, {"direction": direction, "isolated": False, "policies": [], "reason": "not isolated"}
    allowed = []
    for p in policies:
        rules = p["spec"].get(direction.lower(), [])
        if any(rule_matches(snapshot, p, rule, contract, direction) for rule in rules):
            allowed.append(f'{p["metadata"]["namespace"]}/{p["metadata"]["name"]}')
    return bool(allowed), {"direction": direction, "isolated": True, "policies": sorted(allowed),
                           "reason": "matching allow rule" if allowed else "isolated: no matching allow rule"}


def ensure_deterministic(snapshot: Snapshot, contracts: tuple[Contract, ...]) -> None:
    # ipBlock with Pod IP is CNI-dependent; do not make a definitive allow/deny claim.
    pod_addrs = {ipaddress.ip_address(p["ip"]) for p in snapshot.pods.values()}
    for policy in snapshot.policies:
        for direction in ("ingress", "egress"):
            field = "from" if direction == "ingress" else "to"
            for rule in policy["spec"].get(direction, []):
                for p in rule.get(field, []):
                    if "ipBlock" in p:
                        block = p["ipBlock"]
                        net = ipaddress.ip_network(block["cidr"])
                        for addr in pod_addrs:
                            if addr in net and not any(addr in ipaddress.ip_network(x) for x in block.get("except", [])):
                                raise InputError("ipBlock overlaps inventoried Pod IP: CNI-dependent, cannot model safely")


def evaluate(snapshot: Snapshot, contract: Contract) -> dict[str, Any]:
    egress_ok, out = directional(snapshot, contract, "Egress")
    ingress_ok, inside = directional(snapshot, contract, "Ingress")
    allowed = egress_ok and ingress_ok
    return {"id": contract.id, "source": contract.source, "destination": contract.destination,
            "protocol": contract.protocol, "port": contract.port, "expected": contract.expect,
            "actual": "allow" if allowed else "deny", "pass": allowed == (contract.expect == "allow"),
            "severity": contract.severity, "reason": contract.reason, "egress": out, "ingress": inside}


def run_audit(snapshot: Snapshot, contracts: tuple[Contract, ...]) -> dict:
    ensure_deterministic(snapshot, contracts)
    findings = [evaluate(snapshot, c) for c in contracts]
    findings.sort(key=lambda e: e["id"])
    return {"schema": "netpol.contractguard/report-v1", "mode": "audit", "summary": {
        "contracts": len(findings), "violations": sum(not f["pass"] for f in findings)}, "results": findings}


def run_compare(before: Snapshot, after: Snapshot, contracts: tuple[Contract, ...]) -> dict:
    from .model import same_inventory
    same_inventory(before, after)
    ensure_deterministic(before, contracts)
    ensure_deterministic(after, contracts)
    rows = []
    for c in contracts:
        old, new = evaluate(before, c), evaluate(after, c)
        drift = ("new-exposure" if old["actual"] == "deny" and new["actual"] == "allow" else
                 "connectivity-loss" if old["actual"] == "allow" and new["actual"] == "deny" else "unchanged")
        rows.append({**new, "before": old["actual"], "drift": drift,
                     "baselinePass": old["pass"]})
    rows.sort(key=lambda item: item["id"])
    return {"schema": "netpol.contractguard/report-v1", "mode": "compare", "summary": {
        "contracts": len(rows), "violations": sum(not f["pass"] for f in rows),
        "newExposures": sum(f["drift"] == "new-exposure" for f in rows),
        "connectivityLosses": sum(f["drift"] == "connectivity-loss" for f in rows)}, "results": rows}


def verdict(report: dict, threshold: str) -> bool:
    if threshold == "none":
        return False
    minimum = SEVERITIES.index(threshold)
    return any(not item["pass"] and SEVERITIES.index(item["severity"]) >= minimum
               for item in report["results"])


def sarif(report: dict) -> dict:
    findings = []
    for r in report["results"]:
        if r["pass"]:
            continue
        ruleid = "NCG001" if r["expected"] == "deny" else "NCG002"
        message = f'{r["id"]}: expected {r["expected"]}, observed {r["actual"]} ({r["source"]} -> {r["destination"]} {r["protocol"]}/{r["port"]})'
        findings.append({"ruleId": ruleid,
                         "level": "error" if r["severity"] in ("high", "critical") else "warning",
                         "message": {"text": message},
                         "partialFingerprints": {"primaryLocationLineHash": hashlib.sha256(r["id"].encode()).hexdigest()[:24]},
                         "properties": {"contractId": r["id"], "severity": r["severity"],
                                        "drift": r.get("drift", "audit"), "reason": r["reason"]}})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "NetPol ContractGuard", "semanticVersion": "0.1.0",
                                         "rules": [{"id": "NCG001", "shortDescription": {"text": "Unexpected connectivity exposure"}},
                                                   {"id": "NCG002", "shortDescription": {"text": "Expected connectivity is denied"}}]}},
                      "results": findings}]}
