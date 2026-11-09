"""Negative, malformed, ambiguous and fuzzed parser regression tests."""
from __future__ import annotations
import copy
import json
import tempfile
import unittest
from pathlib import Path

from netpol_contract_guard.model import InputError, parse_snapshot, parse_contracts, read_json
from test_semantics import fixture, contract, contracts, policy

class Validation(unittest.TestCase):
    def expect_bad(self,change):
        doc=fixture();change(doc)
        with self.assertRaises(InputError): parse_snapshot(doc)

    def test_snapshot_missing_fields(self):
        for field in ('apiVersion','namespaces','pods','policies'):
            with self.subTest(field=field):self.expect_bad(lambda d:d.pop(field))

    def test_snapshot_unknown_fields(self):
        self.expect_bad(lambda d:d.update({'arbitrary':True}))

    def test_wrong_api_version(self):
        self.expect_bad(lambda d:d.update({'apiVersion':'v0'}))

    def test_duplicate_namespace(self):
        self.expect_bad(lambda d:d['namespaces'].append(copy.deepcopy(d['namespaces'][0])))

    def test_duplicate_pod(self):
        self.expect_bad(lambda d:d['pods'].append(copy.deepcopy(d['pods'][0])))

    def test_duplicate_pod_ip(self):
        self.expect_bad(lambda d:d['pods'][1].update({'ip':d['pods'][0]['ip']}))

    def test_unknown_pod_namespace(self):
        self.expect_bad(lambda d:d['pods'][0].update({'namespace':'missing'}))

    def test_unknown_policy_namespace(self):
        self.expect_bad(lambda d:d['policies'][0]['metadata'].update({'namespace':'missing'}))

    def test_duplicate_policy(self):
        self.expect_bad(lambda d:d['policies'].append(copy.deepcopy(d['policies'][0])))

    def test_invalid_host_or_port(self):
        for bad in (0,65536,True,'80',-2,None):
            with self.subTest(bad=bad):self.expect_bad(lambda d:d['pods'][1]['ports'][0].update({'port':bad}))

    def test_invalid_policy_port(self):
        for value in (True,65536,0,-1,None):
            with self.subTest(value=value):self.expect_bad(lambda d:d['policies'][0]['spec']['egress'][0]['ports'][0].update({'port':value}))

    def test_invalid_end_port(self):
        for v in (0,70000,True,800):
            with self.subTest(v=v): self.expect_bad(lambda d:d['policies'][0]['spec']['egress'][0]['ports'][0].update({'endPort':v}))

    def test_named_end_port_disallowed(self):
        self.expect_bad(lambda d:d['policies'][1]['spec']['ingress'][0]['ports'][0].update({'endPort':9000}))

    def test_invalid_selector_operator(self):
        def change(d):d['policies'][0]['spec']['podSelector']['matchExpressions']=[{'key':'app','operator':'NotThing'}]
        self.expect_bad(change)

    def test_invalid_expression_key(self):
        for key in (['x'],{},23,True,'*'*254):
            def change(d):d['policies'][0]['spec']['podSelector']['matchExpressions']=[{'key':key,'operator':'Exists'}]
            with self.subTest(key=str(key)[:16]):self.expect_bad(change)

    def test_invalid_policy_types(self):
        for types in ([{},'Egress'],['Ingress','Ingress'],['Unknown'],[],[1]):
            with self.subTest(types=types):self.expect_bad(lambda d:d['policies'][0]['spec'].update({'policyTypes':types}))

    def test_invalid_peer_mixed_block_selector(self):
        self.expect_bad(lambda d:d['policies'][1]['spec']['ingress'][0]['from'][0].update({'ipBlock':{'cidr':'203.0.113.0/24'}}))

    def test_invalid_cidr(self):
        for ip in ('not a CIDR','10.0.0.1/24','10.0.0.0/500',42):
            with self.subTest(ip=ip):
                def change(d):d['policies'][1]['spec']['ingress'][0]['from']=[{'ipBlock':{'cidr':ip}}]
                self.expect_bad(change)

    def test_invalid_cidr_except(self):
        def change(d):d['policies'][1]['spec']['ingress'][0]['from']=[{'ipBlock':{'cidr':'198.51.100.0/24','except':['203.0.113.0/24']}}]
        self.expect_bad(change)

    def test_contract_unknown_endpoint(self):
        snap=parse_snapshot(fixture())
        for endpoint in ('unknown/pod','ip:not-ip'):
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(InputError):contracts(snap,[contract(destination=endpoint)])

    def test_contract_external_to_external_rejected(self):
        snap=parse_snapshot(fixture())
        with self.assertRaises(InputError):contracts(snap,[contract('ip:198.51.100.1','ip:203.0.113.1')])

    def test_contract_pod_ip_alias_rejected(self):
        snap=parse_snapshot(fixture())
        with self.assertRaises(InputError):contracts(snap,[contract('ip:10.244.1.10')])

    def test_contract_self_traffic_rejected(self):
        snap=parse_snapshot(fixture())
        with self.assertRaises(InputError):contracts(snap,[contract('web/client','web/client')])

    def test_contract_duplicate_id(self):
        snap=parse_snapshot(fixture())
        with self.assertRaises(InputError):contracts(snap,[contract(),contract()])

    def test_contract_invalid_values(self):
        snap=parse_snapshot(fixture())
        for key,value in [('expect','pass'),('severity','emergency'),('protocol','ICMP'),('port',0),('port',True),('id','bad id')]:
            item=contract(); item[key]=value
            with self.subTest(key=key):
                with self.assertRaises(InputError):contracts(snap,[item])

    def test_max_snapshot_limits(self):
        self.expect_bad(lambda d:d.update({'pods':d['pods']*101}))
        self.expect_bad(lambda d:d.update({'policies':d['policies']*126}))

    def test_read_json_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'file.json';p.write_text('{"x":1,"x":2}')
            with self.assertRaises(InputError):read_json(p)

    def test_read_json_nan(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'file.json';p.write_text('{"x": NaN}')
            with self.assertRaises(InputError):read_json(p)

    def test_read_json_symlink(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'file.json';p.write_text('{}')
            link=Path(t)/'link.json'
            try:link.symlink_to(p)
            except OSError:self.skipTest('symlinks not available')
            with self.assertRaises(InputError):read_json(link)

    def test_read_json_oversize(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'file.json';p.write_bytes(b' '*2_000_001)
            with self.assertRaises(InputError):read_json(p)

    def test_reject_nonobject_policies(self):
        for value in (False,None,23,[]):
            with self.subTest(value=value):self.expect_bad(lambda d:d['policies'].append(value))

if __name__=='__main__':unittest.main()
