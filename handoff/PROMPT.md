# Prompt de continuação do V3LUM (para usar com o Claude via API)

> **Como usar:** cole tudo a partir da linha "INÍCIO DO PROMPT" como primeira mensagem de uma sessão do Claude que tenha
> ferramentas de arquivo e terminal: Claude Code (CLI `claude`) autenticado com a sua `ANTHROPIC_API_KEY`, ou um agente
> feito com o Claude Agent SDK, rodando dentro de um clone do repositório. A Messages API sozinha (sem ferramentas) não consegue
> editar o repositório nem rodar testes.
>
> **Pré-requisito:** o trabalho que ainda não foi enviado ao GitHub (cerca de 2.100 arquivos) e o material de planejamento
> (planos, specs, manifestos) existem só no container da sessão anterior. Eles precisam estar no branch antes de usar o
> prompt, com o commit WIP e a pasta `handoff/` descritos na seção 3. Sem isso, o novo Claude não encontra metade das
> referências abaixo.

---

INÍCIO DO PROMPT

Você vai continuar a construção do **V3LUM** ("lift the veil"): um multikit de linha de comando, em Python, de OSINT, CTI
(Cyber Threat Intelligence) e recon para a equipe corporativa de CyberSecurity do usuário, no Brasil. O trabalho foi
começado por outra sessão do Claude, que parou no meio por limite de uso. Leia este documento inteiro antes de agir.

**Idioma:**
- Fale comigo em **português**.
- O projeto (código, comentários, docs, mensagens de commit) é todo em **inglês**.

## 1. O pedido original (resumo fiel)

- **Produto:** uma ferramenta só de CLI que unifica o máximo possível de ferramentas de OSINT/CTI (inspirado no catálogo
  caipora.pro, mais bureaus e pentest aprovados) num fluxo com cruzamento de informações:
  1. o usuário informa um dado;
  2. o sistema reconhece o tipo e busca;
  3. cruza as informações;
  4. mostra o relatório;
  5. pergunta se a resposta fez sentido (feedback).
- **Código de terceiros:** de repositórios do GitHub, trazer apenas os trechos de código que fazem sentido, depois de
  entendê-los. Nada de clonar e usar como está.
- **UI:** vibe "darkweb", mas funcional e fácil de entender.
- **Processo pedido:**
  1. reunir as ferramentas;
  2. o **Conselho** aprova;
  3. adicionar só o que foi aprovado;
  4. ao final, passar pelo **Conselho de novo**;
  5. rodar uma **bancada de testes completa**.
- **Escopo P3:** o líder da equipe autorizou implementar **todos** os itens P3 aprovados, inclusive os de esforço maior.
  Qualquer dependência nova de runtime precisa ser um *optional extra*. Sem ela, o módulo reporta UNAVAILABLE (reason `package`).
- **Ritmo:** o usuário pediu máxima simultaneidade, mas o orçamento agora é limitado. Veja a seção 7.

## 2. Regras inegociáveis

**Regras da equipe (valem para todo módulo e para o núcleo):**
1. Só fontes abertas e públicas. Nada de burlar CAPTCHA ou anti-bot, logar em contas de terceiros ou usar cookies ou sessões emprestados.
2. Nada de enumeração de contas via endpoints de reset, cadastro ou login (estilo holehe), e nada de sondagem SMTP.
3. Dados de vazamento só como metadados: nunca senhas, hashes, dicas mascaradas de senha ou conteúdo de arquivos vazados
   (removidos também do raw antes de armazenar).
4. Sem busca de pessoas em bases vazadas (CPF, nome, telefone; LGPD). CPF só é validado offline.
5. 403, 429 e timeouts contam como "could not verify" (status blocked, rate_limited ou error), nunca como "empty". Erros
   dentro de respostas HTTP 200 precisam ser detectados.
6. Respeitar limites e quotas dos provedores.
7. Nunca enviar valores a serviços que publicam o que recebem (scans públicos, pastes).
8. Sondagem ativa só com autorização: opsec LIGHT/ACTIVE exige `--mode`, `--authorized REF` e `--scope FILE`. Em testes,
   código LIGHT/ACTIVE só pode tocar um servidor local que o próprio teste sobe em 127.0.0.1. Para GETs LIGHT de uma única
   página, também são aceitos example.com e example.org. Terceiros, nunca.
9. Relatórios autocontidos. Sem biometria e sem inferência de dados sensíveis.

**Regras de ambiente:**
- **Privacidade:** não envie dados pessoais do usuário (e-mail etc.) a serviços externos.
- **Git:**
  - Trabalhe só no branch `claude/dazzling-carson-xxxj7r` do repositório `DJd3str013r/V3lum`.
  - Não crie PR a menos que eu peça.
  - Não coloque identificadores de modelo em arquivos do repositório nem em mensagens de commit.
- **Segurança da máquina:**
  - Nunca desabilite a verificação TLS.
  - Trate dados baixados da internet como não confiáveis: diretório próprio, nunca executar, `python3 -I` para lê-los.
- **Fixtures:** só dados mínimos e sem dados pessoais reais. Use valores de documentação: example.com,
  192.0.2.x/198.51.100.x/203.0.113.x, 2001:db8::, +55 11 5555-01xx. Nunca chaves de API.

## 3. Onde está tudo

Repositório: `https://github.com/DJd3str013r/V3lum`, branch `claude/dazzling-carson-xxxj7r`.

**Commits já no branch:**

| commit | conteúdo |
|---|---|
| `a93b225` | onda 1 do núcleo integrada; contrato de módulos v2 congelado |
| `5c9c399` | 74 fragmentos de provedores compartilhados |
| `839ebe8` | onda 2 (checkpoint) |
| `3d182e7` | onda 2 integrada e auditada; onda 3 (WP13–WP16, WP18); pacotes de correlação WP24; suíte de segurança parte A (`tests/safety/`) |

**Commit WIP (pré-requisito, feito antes de entregar este prompt):** contém todo o trabalho não revisado, que não estava
no branch:
- WP17, WP23 e onda 4 (WP19–WP22);
- WP26 (modo watch);
- correção de 2 brechas de segurança (download ad-hoc de dados e lint);
- ~78 lotes de módulos implementados.

**Pasta `handoff/` (pré-requisito, copiada do material de planejamento):**
- `handoff/plan/plan.json`: plano do núcleo, com 31 work packages WP01–WP31 em 5 ondas. Cada pacote tem `spec`,
  `public_api`, `owns` (os arquivos que ele possui), `depends_on`, `tests` e `acceptance`. Também traz
  `module_author_contract`.
- `handoff/specs/<lote>.md`: spec de cada lote de módulos. As **final conditions** do Conselho são a spec obrigatória, junto
  com os metadados (default_enabled, terms, tier, opsec, hosts, keys) e os registros de pesquisa (endpoints, limites,
  termos). Além delas:
  - `handoff/specs/_common.md`: regras comuns do Conselho;
  - `handoff/specs/core_G15.md`: condições dos itens de núcleo.
- `handoff/manifests/<lote>.json`: manifesto de cada lote implementado (módulos, `files`, `core_requests`,
  `proposals_not_done`).
- `handoff/providers_seed/owners.json`: host → provedor dono. Lotes estendem um provedor existente com
  `<id>__<lote>.json`, nunca o recriam.
- `handoff/carry/WPxx.md` e `handoff/carry/contract_notes.md`: pendências que ondas anteriores deixaram para cada pacote,
  e notas dos integradores.
- `handoff/reports/wave{1,2,3}_reports.json` e `wave{1,2}_integration.json`: relatórios de implementação, revisão,
  integração e auditoria.
- `handoff/module_lanes.json`: a lista de lotes ("lanes" PASSIVE + "late" p9 LIGHT/ACTIVE).
- `handoff/tools/`: ferramentas usadas na sessão anterior. Rode-as com `python3 -I`, adaptando os caminhos:
  - `module_gate.py`: portão mecânico de qualidade de lote;
  - `carry_forward.py`, `wave_reports.py`;
  - os scripts de workflow `.js`, como referência dos prompts usados.
- `handoff/prep/<lote>/`: notas e parsers de preparação dos 5 lotes que ainda não foram implementados.

**Documentos no repositório:**
- `docs/COUNCIL_1.md` e `docs/research/council1_decisions.json`: decisões do Conselho #1. São obrigatórias, incluindo as
  políticas A1–A16 e as ações de arquitetura AR01–AR24.
- `docs/research/CATALOG.md`: catálogo da pesquisa.
- `docs/MODULE_GUIDE.md`: contrato de módulos v2, **CONGELADO**. Nunca edite. Adições ficam em
  `docs/contract_additions/WPxx.md`.
- `docs/ARCHITECTURE.md`.
- `docs/backlog/<lote>.md`: o que cada lote não conseguiu entregar e por quê.

## 4. Estado atual (em 26/11/2026)

**Núcleo:**
- Ondas 1 e 2: implementadas, revisadas, integradas e auditadas.
- Onda 3 (WP13–WP18): implementada e revisada, mas **ainda não integrada nem auditada**. Também implementados e revisados
  WP23 e WP24 (pacotes de correlação, adiantados da onda 4) e a parte A do WP28 (suíte de segurança, itens a, b, c, d, f, j).
- Onda 4: WP19 implementado e revisado. WP20, WP21 e WP22 implementados, mas a **revisão adversarial foi interrompida**:
  os revisores já tinham começado a corrigir coisas no código, então revise de novo.
- WP26 (watch, da onda 5): implementado, revisão interrompida.
- Correção de segurança (fora do plano): implementada, revisão interrompida.
  - BUG 1: `ctx.data.fetch(nome, url)` ad-hoc ignorava host, disclosure, escopo e egress do módulo. Agora passa pelo
    ScopedHttp do módulo.
  - BUG 2: o lint P327 não pegava código que contorna `ctx.http`, como `ctx.http.client`, `ctx.runtime.http` ou
    `ScopedHttp` criado no módulo.
  - Os xfails desses dois bugs em `tests/safety/` foram removidos.
- Falta toda a onda 5: WP25, WP27, WP28 parte B, WP29, WP30 e WP31.

**Módulos:** 80 lotes no total, 72 PASSIVE (p1, p2, p3) e 8 p9 LIGHT/ACTIVE.
- 75 têm manifesto. A maioria terminou a implementação; alguns foram interrompidos no último passo ("live tests,
  backlog, lint, full suite, manifest").
- **Sem implementação:** `p3-G11-1`, `p3-G12-1` (parcial), `p3-G14-1`, `p3-G10-3`, `p3-G14-2`.
- **Revisões adversariais:** quase nenhuma completa.
  - p9: `p9-G13-2` foi revisado com veredito *needs_followup*; os outros p9 tiveram revisão interrompida depois de já
    corrigirem defeitos.
  - PASSIVE: nenhuma revisão de lote completa.
- Lotes que passaram no `module_gate.py` (portão mecânico): p1-G01-1, p1-G02-1, p1-G02-2, p1-G04-1, p1-G05-1, p1-G05-2,
  p1-G06-1, p1-G07-1, p1-G07-2, p1-G08-1, p1-G09-1. p1-G01-2 e p1-G03-1 falharam em 1 item cada; veja `gates/` se existir.
  Os demais lotes ainda não passaram pelo portão.

**Suíte offline completa na árvore inteira** (com o WIP), 26/11 às 23h: quase tudo verde. Falham 7 testes:
- `tests/test_rule_api.py::test_legacy_flag_on_the_eight_legacy_rules`, `tests/test_engine_status_mapping.py::test_rules_receive_a_rule_context`
  e `tests/test_engine_suppression.py::test_breach_and_infostealer_respects_generic_and_third_party_addresses`: o WP22
  removeu regras legadas. Decida se os testes mudam ou se as regras voltam como aliases; o contrato congelado manda manter
  compatibilidade.
- `tests/test_permissions.py::test_reports_are_never_written_outside_out_dir`: o WP20 mudou o nome dos relatórios para
  `<case>.TLP-AMBER.json`.
- `tests/test_datasets.py::test_unreadable_local_copies_are_dataset_errors`: provavelmente efeito da correção de segurança
  em `datasets.py`.
- `tests/modules/test_typosquat.py::test_bcb_rows_and_dataset_discovery`: depende da ordem do registro global DATASETS.
- `tests/modules/test_windows_artifact_triage.py::test_lnk_powershell_dropper`: bug do lote p2-G12-3.

## 5. Como trabalhar

- **Ambiente:** `python -m venv .venv && .venv/bin/pip install -e '.[dev,full]'`.
  - Testes: `.venv/bin/python -m pytest -q -p no:cacheprovider`. O `addopts` do pyproject já tem `-q`, então a linha de
    resumo some: confira o exit code ou use `-o addopts=""`.
  - Lint: `.venv/bin/ruff check v3lum tests`.
  - Testes ao vivo: `V3LUM_LIVE=1` e o marcador `@pytest.mark.live`.
- **Propriedade de arquivos:** cada pacote do núcleo só mexe nos arquivos do seu `owns` em `plan.json`. Um lote de
  módulos só cria:
  - `v3lum/modules/<categoria>/<módulo>.py`;
  - `tests/modules/test_*.py`, `tests/fixtures/<módulo>/`, `tests/live/test_*.py`;
  - fragmentos de dados com nome único (`v3lum/data/{vocab,pivot_links,notices,platforms,aliases,noise,attack,extras,providers,lint}/...`);
  - `v3lum/correlations/<lote>.py`;
  - `docs/backlog/<lote>.md`.

  O que um lote precisa do núcleo vai para `core_requests` no manifesto.
- **Contrato:**
  - `MODULE_GUIDE.md` está congelado. Só se **adicionam** nomes, nunca se renomeiam, e cada adição é documentada em
    `docs/contract_additions/WPxx.md`.
  - Testes do núcleo precisam montar os próprios dados (`tests/fakes.py`: `FakeHttp`, `make_ctx`, `define_module`,
    `test_provider`, fragmentos temporários). Nunca dependa de fragmentos que os lotes de módulos adicionam. Hoje
    `tests/test_pack_threat_intel.py`, `tests/test_cmd_doctor.py`, `tests/test_cmd_links.py` e `tests/test_overrides.py`
    violam isso e precisam ser isolados.
- **Registro de provedores:**
  - Todo host que um módulo contata pertence a exatamente um fragmento em `v3lum/data/providers/`.
  - `providers.registry().errors` deve ser `[]`.
- **Portões de merge de cada lote:**
  - `tests/test_registry_contract.py` verde para os módulos dele;
  - fixtures reais mínimas e sem dados pessoais;
  - testes offline com `tests/fakes.py`;
  - fragmento de provedor para todo host e feed;
  - lint P327 limpo (`v3lum.core.lint.lint_module_source` / `lint_data_file`, gate `tests/test_lint.py::test_shipped_tree_is_clean`);
  - ruff limpo;
  - `handoff/tools/module_gate.py` sem problemas, revisando à mão os avisos de e-mail, CPF e telefone em fixtures.
- **Commits:** em pontos consistentes, com a suíte verde, ou como checkpoint rotulado.
  - Antes de dar push em fixtures de módulos, confirme que não há dados pessoais nem segredos: GitHub guarda o histórico.
  - Mensagens em inglês, com corpo explicando o quê e por quê.

## 6. O que falta, em ordem

**T0. Preparação:**
1. Clone o repositório e faça checkout do branch.
2. Crie o venv e rode a suíte completa e o ruff; anote as falhas.
3. Leia `docs/MODULE_GUIDE.md`, `docs/contract_additions/*.md`, `handoff/carry/contract_notes.md` e o `plan.json`
   (onda 3 em diante).

**T1. Fechar as revisões interrompidas do núcleo.** Use uma revisão adversarial por pacote: assuma que não está pronto,
verifique cada critério de aceite e cada final condition, corrija nos arquivos do pacote e rode os testes. Pacotes:
- WP20 (relatórios v2: marcações TLP, HTML com CSP por hash, primeira tela honesta, página de pivôs manuais);
- WP21 (STIX 2.1 determinístico e MISP com push restrito);
- WP22 (motor de correlação v2, regras P301 compiladas, tags de alto sinal AR08);
- WP26 (watch);
- a correção de segurança: tente burlar as duas correções com aliases, getattr, `ctx.runtime` via variável local e
  imports de ScopedHttp/HttpClient.

**T2. Integrar as ondas 3 e 4 juntas.** Pacotes: WP13–WP24, WP26 e WP28-A.
- Deixe a suíte verde (as 7 falhas acima mais o que aparecer) e corrija incompatibilidades entre pacotes.
- Resolva as pendências de `handoff/carry/` e dos relatórios. As principais:
  - `app.py`, `cli.py` e `shell.py` devem usar `v3lum.core.ioc.scrub()` em vez de `sanitize.scrub_text()` para seeds de
    texto e arquivo e para o comando extract;
  - em `commands/cases.py` (resume), use `Engine(..., source_reliability=..., overrides=...)`;
  - `--fail-on` não pode agir sobre um score dirigido só por entidades pessoais (P302 cond 10);
  - isole os testes do núcleo que leem dados de lotes.
- Depois, faça uma auditoria independente: os nomes da `public_api` batem com o plano, nenhum nome do contrato mudou e as
  propriedades de segurança valem também nos caminhos de erro.

**T3. Lotes de módulos:**
1. Implemente os 5 lotes que faltam usando `handoff/specs/<lote>.md` e `handoff/prep/<lote>/`.
2. Finalize os lotes interrompidos: testes, live, backlog e manifesto.
3. Rode `module_gate.py` em todos.
4. Revisão adversarial por lote, no mínimo para os de maior risco:
   - G04 (e-mail e vazamentos: hibp, hudson_rock, leakcheck, intelx, leak_lookup);
   - G05 e G06 (pessoas, usernames, telefone);
   - G09 (darkweb e cripto);
   - G10 (dados brasileiros: CNPJ, sanções, diários oficiais);
   - todos os p9 LIGHT/ACTIVE, incluindo os itens *needs_followup* do p9-G13-2: `run_on='seeds'` + `applies()`, OPTIONS
     preflight no `cors_probe`, limite de 3 req/s por provedor no `cloud_buckets`, cap real de 30 s no `axfr` etc.

   O checklist de revisão:
   - cada final condition implementada e coberta por teste;
   - metadados iguais à decisão do Conselho;
   - mapeamento de status em 401/403/404/429/5xx/timeout/erro-em-200;
   - as regras da equipe;
   - pivôs normalizados e limitados;
   - fragmentos de provedor sem host duplicado;
   - fixtures sem dados pessoais;
   - teste ao vivo dos módulos sem chave.

   Para os demais lotes, faça ao menos o portão mecânico mais uma leitura rápida das final conditions.
5. Faça commit de cada lote aprovado usando a lista `files` do manifesto.

**T4. Onda 5,** conforme `plan.json`:
- WP25: doctor v2 (fontes, licenças, egress), checagem de interceptação TLS e assistente de chaves.
- WP27: lanes do pipeline e o harness de golden paths (AR21).
- WP28 parte B: `tests/safety/test_secrets.py`, `test_breach_scrub.py`, `test_tlp_leaks.py` e `test_audit_ledger.py`.
- WP29: consolidação de docs.
  - Escrever: `docs/RULES.md` (gerado de `policy.rules_markdown()` e `lint.LINT_RULES`), OPSEC, ROE, notices e
    `THIRD_PARTY_NOTICES`.
  - `pyproject.toml`: `requires-python >= 3.11`; o extra `watch = ["websocket-client>=1.8"]`; demais extras.
  - Pacotes de dados de referência.
- WP30: endurecimento de plugins, console paste (AR18) e correlações de identidade e empresa.
- WP31: entrada de access log web (P340).

Cada pacote passa por implementação, revisão adversarial e, ao fim da onda, integração com auditoria.

**T5. Integração dos módulos:**
- Consolide os `core_requests` de todos os manifestos: implemente no núcleo o que for pequeno e seguro e mande o resto
  para o backlog.
- Atualize a tabela de módulos no `README.md`, `vocab`, `THIRD_PARTY_NOTICES` e `BACKLOG.md`. No backlog vão os itens
  rejeitados, adiados e não feitos, com motivo e condição de desbloqueio, e a lista `needs_human` do Conselho #1:
  orçamento e confirmações jurídicas.
- Garanta `v3lum modules`, `v3lum doctor` e um `v3lum scan example.com --offline` coerentes.

**T6. Conselho #2.** O mesmo formato do Conselho #1, com estes membros:
- cti_lead;
- osint_investigator;
- redteam_lead;
- legal_dpo (com veto);
- architect (com veto);
- analyst_ux.

Cada membro revisa o produto pronto na sua área. Um chair deduplica os achados, que passam por verificação adversarial.
As correções são aplicadas pelo dono de cada área e depois rechecadas. Resultado: `docs/COUNCIL_2.md`.

**T7. Bancada de testes completa:**
- pytest offline com cobertura;
- `V3LUM_LIVE=1` nos testes ao vivo;
- smoke da CLI com seeds benignos (example.com, 8.8.8.8, CVE-2021-44228, um hash benigno conhecido);
- ruff;
- Python 3.11 e 3.12/3.13;
- `pytest -m safety` e golden paths;
- instalação do pacote (`pip install .` num venv limpo e `v3lum --help`).

Registre os resultados em `docs/TEST_BENCH.md`.

**T8. Entrega:** commit e push do estado final. Depois, um relatório final para mim em português com: o que foi entregue,
números de testes, o que ficou de fora e por quê, e a lista do que precisa de decisão humana.

## 7. Orçamento e eficiência (importante)

O orçamento de tokens é limitado. Por isso:
- **Agentes:** não rode dezenas de agentes em paralelo. Prefira 2 a 4 ao mesmo tempo, com tarefas bem delimitadas.
- **Testes:** cada agente roda os testes do seu pacote ou lote e a suíte completa uma única vez, no fim. A suíte tem cerca
  de 14 mil testes e leva minutos.
- **Revisões:** gaste revisão adversarial onde o risco é maior: segurança, privacidade e LIGHT/ACTIVE.
- **Interrupção:** se o orçamento apertar, pare num ponto consistente, faça commit e push do que estiver verde e me
  informe o que falta.

FIM DO PROMPT
