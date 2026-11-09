"""Reproduce safe, entirely fictional fixtures; no cluster credentials."""
from __future__ import annotations
import json
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / 'examples'

def pol(name, ns, pod_labels, types, ingress=None, egress=None):
    return {'apiVersion':'networking.k8s.io/v1','kind':'NetworkPolicy',
            'metadata':{'name':name,'namespace':ns},
            'spec':{'podSelector':{'matchLabels':pod_labels}, 'policyTypes':types,
                    'ingress': ingress or [], 'egress':egress or []}}

namespaces = [{'name':'web','labels':{'team':'frontend'}}, {'name':'api','labels':{'team':'backend'}},
              {'name':'data','labels':{'team':'storage'}}]
pods = [
    {'name':'client','namespace':'web','ip':'10.244.1.10','labels':{'app':'client'}},
    {'name':'service','namespace':'api','ip':'10.244.2.10','labels':{'app':'service'},'ports':[{'name':'http','port':8080}]},
    {'name':'db','namespace':'data','ip':'10.244.3.10','labels':{'app':'db'},'ports':[{'name':'postgres','port':5432}]},
    {'name':'rogue','namespace':'data','ip':'10.244.3.11','labels':{'app':'rogue'}}]

policy_web = pol('web-egress','web',{},['Egress'],egress=[{
  'to':[{'namespaceSelector':{'matchLabels':{'kubernetes.io/metadata.name':'api'}},'podSelector':{'matchLabels':{'app':'service'}}}],
  'ports':[{'port':8080}]}])
policy_api_in = pol('api-ingress','api',{'app':'service'},['Ingress'],ingress=[{
  'from':[{'namespaceSelector':{'matchLabels':{'team':'frontend'}},'podSelector':{'matchLabels':{'app':'client'}}}],
  'ports':[{'port':'http'}]}])
policy_api_out = pol('api-egress','api',{'app':'service'},['Egress'],egress=[{
  'to':[{'namespaceSelector':{'matchLabels':{'team':'storage'}},'podSelector':{'matchLabels':{'app':'db'}}}],
  'ports':[{'port':5432}]}])
policy_db_in = pol('db-ingress','data',{'app':'db'},['Ingress'],ingress=[{
  'from':[{'namespaceSelector':{'matchLabels':{'team':'backend'}},'podSelector':{'matchLabels':{'app':'service'}}}],
  'ports':[{'port':'postgres'}]}])
baseline={'apiVersion':'netpol.contractguard/v1','namespaces':namespaces,'pods':pods,
          'policies':[policy_web,policy_api_in,policy_api_out,policy_db_in]}
candidate = deepcopy(baseline)
candidate['policies'].append(pol('bad-additive-allow','data',{'app':'db'},['Ingress'],ingress=[{
  'from':[{'podSelector':{'matchLabels':{'app':'rogue'}}}], 'ports':[{'port':5432}]}]))
contracts={'apiVersion':'netpol.contractguard/v1','contracts':[
    {'id':'WEB_TO_API_HTTP','source':'web/client','destination':'api/service','protocol':'TCP','port':8080,'expect':'allow','severity':'critical','reason':'Web frontend must reach API'},
    {'id':'API_TO_DB_SQL','source':'api/service','destination':'data/db','protocol':'TCP','port':5432,'expect':'allow','severity':'critical','reason':'API requires database'},
    {'id':'ROGUE_TO_DB_DENY','source':'data/rogue','destination':'data/db','protocol':'TCP','port':5432,'expect':'deny','severity':'critical','reason':'Storage namespace lateral movement must be blocked'},
    {'id':'WEB_TO_DB_DENY','source':'web/client','destination':'data/db','protocol':'TCP','port':5432,'expect':'deny','severity':'high','reason':'Frontend must not access database'},
    {'id':'EXTERNAL_TO_API_DENY','source':'ip:203.0.113.20','destination':'api/service','protocol':'TCP','port':8080,'expect':'deny','severity':'high','reason':'No direct external ingress to API'}
]}
for name, content in [('baseline.json',baseline),('candidate-risky.json',candidate),('contracts.json',contracts)]:
    (ROOT/name).write_text(json.dumps(content,indent=2,ensure_ascii=False)+'\n', encoding='utf-8')
