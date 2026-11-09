# NetPol ContractGuard

**Contratos de conectividade e bloqueio de regressões para Kubernetes NetworkPolicy — sem acesso ao cluster.**

[![CI](https://github.com/felipewatter/netpol-contract-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/felipewatter/netpol-contract-guard/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/felipewatter/netpol-contract-guard)](https://github.com/felipewatter/netpol-contract-guard/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)

**English:** [README.en.md](README.en.md). Desenvolvido por [Felipe Watter](https://github.com/felipewatter).

## Por que existe?

A revisão de um `NetworkPolicy` pode parecer simples, mas os detalhes importam: policies são **aditivas**, isolamento de **ingress** e **egress** é avaliado **separadamente**, seletores vazios podem abrir tráfego, e o `podSelector` de uma policy só seleciona Pods do mesmo namespace. Uma alteração aparentemente inocente pode permitir comunicação lateral entre serviços.

O NetPol ContractGuard responde a perguntas operacionais bem delimitadas:

- O frontend ainda consegue alcançar a API na porta 8080?
- O banco permanece inacessível para um Pod não autorizado?
- A mudança de uma policy introduziu **nova exposição**, ou interrompeu um fluxo autorizado?
- Qual direção (ingress ou egress) está bloqueando a conexão?
- O resultado pode bloquear um pull request via **exit code** e ser exportado para JSON/SARIF?

**O diferencial é um conjunto de expectativas explícitas** (`allow` / `deny`) com avaliação reproduzível em snapshots antes/depois. Não busca ser um resolvedor completo de conectividade Kubernetes, nem se declara pioneiro: ferramentas mais amplas como [NP-Guard](https://github.com/np-guard/network-config-analyzer) já implementam análise semântica de políticas.

## Funcionalidades implementadas

| Capacidade | Comportamento |
| --- | --- |
| Contract-as-Code | Conexões com origem, destino, protocolo, porta, expectativa, justificativa e severidade |
| Avaliação bidirecional | Ingress do destino **e** egress da origem precisam permitir |
| Isolamento implícito | Sem policy selecionando um Pod, aquela direção permanece não isolada |
| União de políticas | Uma regra de permissão de qualquer policy aplicável libera a direção |
| Seletores Kubernetes | `matchLabels` e `matchExpressions` (`In`, `NotIn`, `Exists`, `DoesNotExist`) |
| Namespace e Pod selectors | Respeita escopo local, combinação AND e labels imutáveis de namespace |
| IP/CIDR | `ipBlock.cidr`, `except`, IPv4 e IPv6, com salvaguarda sobre IPs de Pods |
| Portas | TCP, UDP, SCTP; numéricas, `endPort`, nomeadas quando destino é Pod inventariado |
| Comparação | Classifica `new-exposure`, `connectivity-loss` e `unchanged` |
| Gate | `--fail-on low\|medium\|high\|critical\|none`; códigos 0, 2 e 3 |
| Relatórios | Texto, JSON estruturado e SARIF 2.1.0 |
| Robustez | JSON duplicado rejeitado, limites de tamanho, campos desconhecidos rejeitados, sem rede |
| Entrega | Testes adversariais, CI multiplataforma e releases imutáveis somente após CI verde |

## Instalação

Requer **Python 3.11 ou superior**. Não há dependências de execução adicionais.

```bash
git clone https://github.com/felipewatter/netpol-contract-guard.git
cd netpol-contract-guard
python -m pip install --no-deps -e .
netpol-contract-guard --version
```

Não é necessário `kubectl`, token de API, kubeconfig, CNI, permissões de cluster ou acesso de rede.

## Uso rápido — em 1 minuto

**1. Avalie a configuração base (deve passar):**

```bash
netpol-contract-guard audit \
  --snapshot examples/baseline.json \
  --contracts examples/contracts.json \
  --fail-on high
```

**2. Compare uma mudança com regressão (deve bloquear):**

```bash
netpol-contract-guard compare \
  --before examples/baseline.json \
  --after examples/candidate-risky.json \
  --contracts examples/contracts.json \
  --fail-on high
```

Exemplo resumido:

```text
NetPol ContractGuard 0.1.0 | mode=compare | gate=blocked
contracts=5 violations=1
FAIL [critical] ROGUE_TO_DB_DENY: data/rogue -> data/db TCP/5432 expected=deny actual=allow drift=new-exposure
```

**3. Exporte o relatório SARIF, consumível por ferramentas de análise estática:**

```bash
netpol-contract-guard compare \
  --before examples/baseline.json \
  --after examples/candidate-risky.json \
  --contracts examples/contracts.json \
  --format json --output report-local.json --sarif findings-local.sarif
```

As saídas com nome de relatório são locais e **nunca podem sobrescrever arquivos de entrada**; **não inclua dados reais ou sensíveis de clusters no repositório**.

**PowerShell (Windows):** use os mesmos comandos em uma única linha, sem barras invertidas:

```powershell
netpol-contract-guard compare --before examples/baseline.json --after examples/candidate-risky.json --contracts examples/contracts.json --fail-on high
```

### Códigos de saída

| Código | Significado |
| --- | --- |
| `0` | Todas as verificações relevantes passaram, ou a política `--fail-on none` foi escolhida explicitamente |
| `2` | Existe pelo menos um contrato violado na severidade especificada |
| `3` | Snapshot inválido, semântica não suportada, ambiente inconsistente ou falha de leitura/gravação |

A opção `--fail-on none` desabilita a **falha do pipeline**, mas ainda registra violações no relatório. Nunca use esse modo para um gate de produção.

## Formato de snapshot

O projeto consome **JSON offline deliberadamente restrito**, não YAML arbitrário nem um dump completo do API server. Policies usam o corpo nativo `networking.k8s.io/v1` apenas com `metadata.name`, `metadata.namespace`, `spec.podSelector`, `policyTypes`, `ingress` e `egress` (e os campos suportados das regras).

```json
{
  "apiVersion": "netpol.contractguard/v1",
  "namespaces": [{"name": "web", "labels": {"team": "frontend"}}],
  "pods": [{"name": "client", "namespace": "web", "ip": "10.244.1.10", "labels": {"app": "client"}}],
  "policies": [
    {
      "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
      "metadata": {"name": "deny-ingress", "namespace": "web"},
      "spec": {"podSelector": {}, "policyTypes": ["Ingress"], "ingress": []}
    }
  ]
}
```

**Uma policy com `ingress: []` isola sem permitir tráfego. Uma regra `ingress: [{}]` permite qualquer peer e qualquer porta.** Essa distinção é parte dos testes, conforme a API oficial.

### Contratos (em arquivo separado, não alterado pelo candidato)

```json
{
  "apiVersion": "netpol.contractguard/v1",
  "contracts": [
    {
      "id": "BLOCK_DB_LATERAL",
      "source": "web/client", "destination": "data/db",
      "protocol": "TCP", "port": 5432,
      "expect": "deny", "severity": "critical",
      "reason": "Frontend não deve alcançar o banco diretamente"
    }
  ]
}
```

O arquivo de contratos é independente dos snapshots. O comando `compare` exige **inventários idênticos** (namespaces/labels, Pods/IPs/portas): a única variação analisada é a política de rede. Isso evita atribuir a uma policy o efeito de uma migração de Pods ou alteração de labels. **Políticas só são analisadas para os fluxos declarados:** sucesso não prova a ausência de outros acessos indesejados.

Veja o modelo completo em [docs/FORMAT.md](docs/FORMAT.md) e o mecanismo em [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Semântica / limites de segurança

O motor reproduz um subconjunto documentado do comportamento esperado das NetworkPolicies **apenas para conexões TCP/UDP/SCTP explícitas entre Pods inventariados e/ou IPs externos**:

1. Política seleciona Pods **dentro de seu próprio namespace**.
2. Um Pod sem NetworkPolicies selecionando determinada direção não está isolado naquela direção.
3. Caso isolado, uma regra de qualquer policy aplicável pode permitir aquela direção.
4. Entre dois Pods, é necessário liberar **saída da origem e entrada do destino**.
5. `namespaceSelector` + `podSelector` no mesmo peer é uma interseção; em peers separados, as alternativas são união.
6. Uma regra com lista de peers/portas ausente ou vazia não restringe aquele atributo; uma lista de regras vazia não permite tráfego.
7. Portas nomeadas são resolvidas no **Pod de destino**, com protocolo compatível.

**Não é um motor de decisão de rede real.** O funcionamento depende de CNI, versão Kubernetes e topologia. O projeto falha explicitamente se o `ipBlock` incluir IP de Pod inventariado, devido à interpretação dependente do CNI. Não modela `hostNetwork`, comunicação com nós, Services/DNAT, NodePorts, NAT, DNS, ICMP, múltiplas interfaces, service mesh, Cilium/Calico CRDs, políticas administrativas, tráfego já estabelecido, readiness, NetworkPolicy com metadados Kubernetes não contemplados, nem a efetiva aplicação em runtime. Um contrato com origem e destino ambos externos é rejeitado.

**O projeto não toca em ambientes de produção e não deve ser usado como autorização final de mudança sem revisão humana e testes de conectividade reais.** Leia [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Testes e CI/CD

```bash
python -m pip install --no-deps -e .
python -m unittest discover -s tests -v
python -m compileall -q src tests scripts
python scripts/build_release.py dist
```

O workflow [`.github/workflows/ci.yml`](.github/workflows/ci.yml) testa 3 sistemas operacionais (Ubuntu, Windows, macOS) e Python 3.11, 3.12 e 3.13 (**9 jobs**). Além da suíte unitária, prova que o caso seguro retorna `0`, o caso de regressão retorna `2` e o pacote é reproduzível.

O workflow [`.github/workflows/release.yml`](.github/workflows/release.yml) usa `workflow_run`: executa **somente após CI verde num push de `main`**; confere a SHA testada com o HEAD atual; reexecuta testes; empacota ZIP, Wheel e checksums; e **não modifica tags e assets de releases anteriores**. Actions externas são fixadas por SHA e o checkout descarta credenciais persistidas. Nenhum segredo de nuvem é requerido.

### Política de releases

- Versionamento SemVer; alterações de CI/build após um release exigem nova versão patch para um release 100% alinhado ao HEAD.
- Nunca reatribuir uma tag existente; não sobrescrever release imutável.
- A tag ref e os artefatos devem corresponder à mesma revisão aprovada pela CI.
- Publicar apenas exemplos sintéticos; não anexar relatórios de produção.
- Ver [CHANGELOG.md](CHANGELOG.md) e [docs/RELEASE_NOTES.md](docs/RELEASE_NOTES.md).

## Contribuição e segurança

**Issues e PRs:** [CONTRIBUTING.md](CONTRIBUTING.md). Divulgação responsável: [SECURITY.md](SECURITY.md). Código de conduta: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). **Licença: MIT** ([LICENSE](LICENSE)).

## Referências técnicas

- [Kubernetes Network Policies (conceitos)](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Kubernetes NetworkPolicy API v1](https://kubernetes.io/docs/reference/kubernetes-api/networking/network-policy-v1/)
- [Label selectors](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/)
- [NP-Guard Network Config Analyzer — implementação independente de referência](https://github.com/np-guard/network-config-analyzer)

Este projeto é uma implementação independente, sem copiar o código das ferramentas citadas. **Não possui vínculo nem chancela do Kubernetes ou do projeto NP-Guard.**
