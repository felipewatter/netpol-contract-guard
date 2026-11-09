"""Kubernetes NetworkPolicy semantics; independent expected observations."""
from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from netpol_contract_guard.engine import evaluate, policy_types, run_audit, run_compare, selected, verdict, sarif
from netpol_contract_guard.model import Contract, InputError, parse_snapshot, parse_contracts

BASE = Path(__file__).resolve().parents[1] / 'examples'

def fixture(name='baseline.json'):
    return json.loads((BASE / name).read_text())

def contracts(snap, entries):
    return parse_contracts({'apiVersion':'netpol.contractguard/v1','contracts':entries}, snap)

def contract(source='web/client', destination='api/service', port=8080, expected='allow', protocol='TCP', severity='high'):
    return {'id':'CHECK', 'source':source, 'destination':destination, 'port':port, 'protocol':protocol,
            'expect':expected, 'severity':severity}

def policy(name='default', namespace='api', select=None, types=None, ingress=None, egress=None):
    spec={'podSelector':{'matchLabels':select or {}}}
    if types is not None: spec['policyTypes']=types
    if ingress is not None: spec['ingress']=ingress
    if egress is not None: spec['egress']=egress
    return {'apiVersion':'networking.k8s.io/v1','kind':'NetworkPolicy',
            'metadata':{'name':name,'namespace':namespace},'spec':spec}

def allow(snapshot, a='web/client', b='api/service', port=8080, protocol='TCP'):
    snap=parse_snapshot(snapshot)
    c=contracts(snap,[contract(a,b,port,protocol=protocol)])[0]
    return evaluate(snap,c)['actual']=='allow'

class Semantics(unittest.TestCase):
    def test_baseline_all_contracts(self):
        snap=parse_snapshot(fixture()); c=parse_contracts(fixture('contracts.json'),snap)
        report=run_audit(snap,c)
        self.assertEqual(report['summary']['violations'],0)
        self.assertFalse(verdict(report,'high'))

    def test_candidate_detects_lateral_exposure(self):
        a=parse_snapshot(fixture()); b=parse_snapshot(fixture('candidate-risky.json'))
        c=parse_contracts(fixture('contracts.json'),a)
        report=run_compare(a,b,c)
        self.assertEqual(report['summary']['newExposures'],1)
        self.assertEqual(report['summary']['violations'],1)
        self.assertTrue(verdict(report,'high'))
        row=next(x for x in report['results'] if x['id']=='ROGUE_TO_DB_DENY')
        self.assertEqual((row['before'],row['actual'],row['drift']),('deny','allow','new-exposure'))

    def test_no_policies_allow_by_default(self):
        doc=fixture(); doc['policies']=[]
        for a,b in [('web/client','api/service'),('data/rogue','data/db')]:
            self.assertTrue(allow(doc,a,b,8080))

    def test_any_side_can_block(self):
        doc=fixture()
        doc['policies']=[p for p in doc['policies'] if p['metadata']['name'] != 'api-ingress']
        self.assertTrue(allow(doc))
        doc['policies']=[p for p in doc['policies'] if p['metadata']['name'] != 'web-egress']
        self.assertTrue(allow(doc))
        doc['policies'].append(policy('deny-egress','web',types=['Egress'],egress=[]))
        self.assertFalse(allow(doc))

    def test_isolation_direction(self):
        doc=fixture(); doc['policies']=[policy(types=['Ingress'],ingress=[])]
        self.assertFalse(allow(doc))
        self.assertTrue(allow(doc,'api/service','data/db',5432))
        doc['policies']=[policy(types=['Egress'],egress=[])]
        self.assertTrue(allow(doc))
        self.assertFalse(allow(doc,'api/service','data/db',5432))

    def test_policy_union_additive(self):
        doc=fixture(); doc['policies']=[policy('closed',ingress=[])]
        self.assertFalse(allow(doc))
        doc['policies'].append(policy('open',ingress=[{}]))
        self.assertTrue(allow(doc))

    def test_omitted_or_empty_peer_port_arrays_match_all(self):
        for rule in [{},{'from':[]},{'ports':[]},{'from':[],'ports':[]}]:
            with self.subTest(rule=rule):
                doc=fixture();doc['policies']=[policy(ingress=[rule])]
                self.assertTrue(allow(doc))

    def test_empty_rule_list_default_deny(self):
        doc=fixture();doc['policies']=[policy(ingress=[])]
        self.assertFalse(allow(doc))

    def test_policyTypes_default_ingress(self):
        self.assertEqual(policy_types({'podSelector':{}}),{'Ingress'})
        self.assertEqual(policy_types({'podSelector':{},'egress':[{}]}),{'Ingress','Egress'})
        self.assertEqual(policy_types({'podSelector':{},'policyTypes':['Egress']}),{'Egress'})

    def test_port_protocol_and_range(self):
        for port, proto, expected in [(8000,'TCP',True),(8002,'TCP',True),(7999,'TCP',False),
                                       (8003,'TCP',False),(8001,'UDP',False),(8080,'TCP',False)]:
            with self.subTest(port=port,proto=proto):
                doc=fixture();doc['policies']=[policy(ingress=[{'ports':[{'port':8000,'endPort':8002}]}])]
                self.assertEqual(allow(doc,port=port,protocol=proto), expected)

    def test_named_port_on_destination(self):
        doc=fixture();doc['policies']=[policy(ingress=[{'ports':[{'port':'http'}]}])]
        self.assertTrue(allow(doc))
        self.assertFalse(allow(doc,port=8081))
        self.assertFalse(allow(doc,protocol='UDP'))

    def test_selector_match_labels(self):
        self.assertTrue(selected({'matchLabels':{'env':'prod'}},{'env':'prod','app':'api'}))
        self.assertFalse(selected({'matchLabels':{'env':'prod'}},{'env':'dev'}))
        self.assertTrue(selected({},{}))

    def test_selector_operators(self):
        cases=[('In',['prod'],{'env':'prod'},True),('In',['prod'],{},False),
               ('NotIn',['prod'],{'env':'stage'},True),('NotIn',['prod'],{},True),
               ('NotIn',['prod'],{'env':'prod'},False),('Exists',[],{'env':'prod'},True),
               ('Exists',[],{},False),('DoesNotExist',[],{},True),
               ('DoesNotExist',[],{'env':'prod'},False)]
        for operator,values,labels,expected in cases:
            with self.subTest(operator=operator,labels=labels):
                self.assertEqual(selected({'matchExpressions':[{'key':'env','operator':operator,'values':values}]},labels), expected)

    def test_pod_selector_without_namespace_scoped_to_policy_namespace(self):
        doc=fixture();doc['policies']=[policy(ingress=[{'from':[{'podSelector':{}}]}])]
        self.assertFalse(allow(doc))
        doc['pods'].append({'name':'same','namespace':'api','ip':'10.244.2.44','labels':{}})
        self.assertTrue(allow(doc,'api/same','api/service'))

    def test_namespace_selector_across_namespaces(self):
        doc=fixture();doc['policies']=[policy(ingress=[{'from':[{'namespaceSelector':{'matchLabels':{'team':'frontend'}}}]}])]
        self.assertTrue(allow(doc))
        self.assertFalse(allow(doc,'data/rogue','api/service'))

    def test_namespace_and_pod_selector_are_intersection(self):
        doc=fixture();doc['policies']=[policy(ingress=[{'from':[{'namespaceSelector':{'matchLabels':{'team':'frontend'}},
                                                  'podSelector':{'matchLabels':{'app':'client'}}}]}])]
        self.assertTrue(allow(doc))
        doc['pods'][0]['labels']['app']='other'
        self.assertFalse(allow(doc))

    def test_empty_peer_matches_all_including_external(self):
        doc=fixture();doc['policies']=[policy(ingress=[{'from':[{}]}])]
        self.assertTrue(allow(doc,'ip:203.0.113.11','api/service'))

    def test_ip_block_and_exceptions(self):
        doc=fixture();doc['policies']=[policy(ingress=[{'from':[{'ipBlock':{
            'cidr':'203.0.113.0/24','except':['203.0.113.128/25']}}]}])]
        self.assertTrue(allow(doc,'ip:203.0.113.1','api/service'))
        self.assertFalse(allow(doc,'ip:203.0.113.160','api/service'))
        self.assertFalse(allow(doc,'ip:198.51.100.5','api/service'))

    def test_ip_block_egress(self):
        doc=fixture();doc['policies']=[policy('out','web',types=['Egress'],egress=[{'to':[{'ipBlock':{'cidr':'198.51.100.0/24'}}]}])]
        self.assertTrue(allow(doc,'web/client','ip:198.51.100.44',443))
        self.assertFalse(allow(doc,'web/client','ip:203.0.113.44',443))

    def test_ip_overlap_fails_closed(self):
        doc=fixture();doc['policies']=[policy(ingress=[{'from':[{'ipBlock':{'cidr':'0.0.0.0/0'}}]}])]
        snap=parse_snapshot(doc); c=contracts(snap,[contract()])
        with self.assertRaisesRegex(InputError,'CNI-dependent'):
            run_audit(snap,c)

    def test_compare_reject_inventory_changes(self):
        before=fixture(); after=fixture();after['pods'][0]['labels']['app']='changed'
        snap=parse_snapshot(before); c=contracts(snap,[contract()])
        with self.assertRaisesRegex(InputError,'identical'):
            run_compare(snap,parse_snapshot(after),c)

    def test_contract_severity_gate(self):
        snap=parse_snapshot(fixture('candidate-risky.json'))
        c=parse_contracts(fixture('contracts.json'),snap)
        rep=run_audit(snap,c)
        self.assertTrue(verdict(rep,'critical'))
        self.assertFalse(verdict(rep,'none'))
        self.assertEqual(len(sarif(rep)['runs'][0]['results']),1)

    def test_deterministic_report(self):
        snap=parse_snapshot(fixture());c=parse_contracts(fixture('contracts.json'),snap)
        self.assertEqual(run_audit(snap,c),run_audit(snap,c))

if __name__=='__main__':unittest.main()
