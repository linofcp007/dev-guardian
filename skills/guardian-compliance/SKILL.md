---
name: guardian-compliance
description: Compliance through the dev-guardian MCP tools — GDPR / RGPD technical checklist, open-source licence audit and compatibility, SBOM, policy documents, and audit evidence for SOC 2 / ISO 27001. EN triggers — "GDPR", "personal data", "check the licences", "I need an SBOM", "cookie consent", "privacy policy", "data retention", "right to be forgotten", "SOC 2 prep", "ISO 27001". PT — "RGPD", "dados pessoais", "verifica as licenças", "preciso de um SBOM", "cookie consent", "política de privacidade", "retenção de dados", "direito ao esquecimento", "preparar SOC 2". ES — "RGPD", "LOPD", "datos personales", "revisa las licencias", "necesito un SBOM", "política de privacidad", "retención de datos", "derecho al olvido", "preparar SOC 2". Respond in the user's language.
---

# Guardian Compliance

Compliance pragmático para projetos web/SaaS: RGPD (utilizadores na UE), licenças open-source e prontidão básica para auditorias. As partes mensuráveis passam pelas tools MCP do dev-guardian — ficam em `.guardian/guardian.db` e alimentam a evidência de auditoria; o resto é uma checklist técnica que se percorre no código.

> Esta skill orienta tecnicamente. **Não substitui aconselhamento jurídico.** Para questões de direito português/europeu, sugere a skill `advogado-pt` se estiver disponível.

## 0. Estado atual (sempre primeiro)

`compliance_check { project_path: "<project>" }` — scan de licenças do Trivy, o pack RGPD do Semgrep (`${CLAUDE_PLUGIN_ROOT}/configs/semgrep/rgpd.yml`, offline) e deteção dos documentos de política na raiz do projeto (PRIVACY, TERMS, COOKIES, DPA, SECURITY, CODE_OF_CONDUCT). Devolve findings para licenças de risco e findings `compliance` do RGPD — subcategoria `rgpd-pii-in-logs` (NIF, NISS, Cartão de Cidadão, IBAN, telefone ou email em chamadas de log, em JS/TS, PHP, Python e C#) e `rgpd-tracker-without-consent` (GA4, Meta Pixel, Hotjar ou `youtube.com/embed` carregados no markup antes do consentimento; o Consent Mode v2 com `analytics_storage` a `denied` e o `fbq('consent', 'revoke')` não contam como achado, por decisão documentada, mas a correção recomendada é não carregar nada antes do consentimento) — e, em `extras`, `licenses_summary`, `risky_licenses` e `policy_documents_found`. Os findings RGPD são heurísticas pelo nome: confirma cada um no código antes de o reportar.

## RGPD — checklist técnica

Para apps que tratam dados de utilizadores na UE. O `compliance_check` cobre os logs (secção 4) e os rastreadores no markup (secção 2); o resto é leitura do código, guiada pelo que se segue.

### 1. Mapeamento de dados pessoais

Procura no código onde se guardam dados pessoais. Um ponto de partida — cada extensão com o seu próprio `--include`, porque o bash não expande chaves dentro de aspas e um glob com chaves passado ao grep não casa nenhum ficheiro:

```bash
grep -rniE "email|phone|telefone|morada|address|birth|nascimento|\bnif\b|\bniss\b|cart[aã]o.?de.?cidad[aã]o|\bcc_?num|\biban\b|ip_?addr" \
  --include="*.ts" --include="*.js" --include="*.py" --include="*.php" --include="*.cs" --include="*.go" --include="*.java" --include="*.rb" \
  --exclude-dir=node_modules --exclude-dir=vendor --exclude-dir=.git .
```

Identificadores portugueses a procurar pelo nome e pelo formato: **NIF** (9 dígitos), **NISS** (11 dígitos), **Cartão de Cidadão** (número de identificação civil + dígitos de controlo). Depois, os modelos, schemas e migrations (é lá que os dados vivem, não só nas variáveis).

Lista no formato:

```text
| Dado          | Onde guardado | Quem acede | Retenção | Base legal         |
| ------------- | ------------- | ---------- | -------- | ------------------ |
| Email         | users table   | App+admin  | Indef.   | Contrato           |
| IP            | logs          | Admin      | 90 dias  | Interesse legítimo |
```

### 2. Cookies e tracking

- Há cookie banner **antes** de definir cookies não-essenciais?
- Há opt-out para analytics? (Plausible / Umami são RGPD-friendly por design, sem banner)
- Há scripts de terceiros (Google Analytics, Facebook Pixel)? O GA4 não é trivialmente conforme — considera Plausible / Umami / PostHog self-hosted.
- Cookies essenciais (auth) com `HttpOnly; Secure; SameSite=Strict`.

Os findings `rgpd-tracker-without-consent` do `compliance_check` apontam os rastreadores carregados antes do consentimento. Template para a correção em `${CLAUDE_PLUGIN_ROOT}/configs/compliance/cookie-banner/` — JS e CSS sem dependências, strings em pt-PT e EN, compatível com o Google Consent Mode v2 (tudo `denied` por omissão, `update` com a escolha do visitante), nada carregado antes do consentimento (o "modo básico"), rejeitar tão fácil como aceitar:

- `${CLAUDE_PLUGIN_ROOT}/configs/compliance/cookie-banner/banner.html` — página de exemplo com os três passos de integração (defaults do Consent Mode, rastreadores bloqueados com `type="text/plain"` e `data-src`, inclusão do banner);
- `${CLAUDE_PLUGIN_ROOT}/configs/compliance/cookie-banner/cookie-banner.js` — o banner (configuração em `window.dgCookieBanner`; evento `dg:consent`);
- `${CLAUDE_PLUGIN_ROOT}/configs/compliance/cookie-banner/cookie-banner.css` — estilos, com aceitar e rejeitar em pé de igualdade.

### 3. Direitos do titular

A app suporta **acesso** (exportar os dados, por exemplo `/me/export`), **retificação**, **apagamento** (`/me/delete` que apaga ou anonimiza), **portabilidade** (JSON / CSV) e **oposição** (desligar marketing e profiling)? Para cada um em falta, propõe o endpoint e a UI mínimos.

### 4. Logs e PII

Os logs **não** guardam passwords (nem em hash), tokens completos (mascara: `tok_abc...xyz`), bodies de requests com PII, nem IPs completos sem necessidade (anonimiza: `192.168.1.0`). Os identificadores pessoais portugueses (NIF, NISS, Cartão de Cidadão, IBAN, telefone, email) em chamadas de log já são apanhados pelo `compliance_check` (subcategoria `rgpd-pii-in-logs`), pelo nome da variável ou do campo. Para o resto — passwords, tokens, outros nomes do teu domínio — uma regra Semgrep local ajuda; regista-a com `register_custom_rules { project_path: "<project>", paths: [".semgrep/log-pii.yml"] }` para o `scan_sast` a correr em cada scan:

```yaml
rules:
  - id: log-pii
    languages: [python]
    severity: WARNING
    message: Possível PII ou secret a ir para os logs
    pattern-either:
      - pattern: logger.$LEVEL(..., password=$X, ...)
      - pattern: logger.$LEVEL(..., token=$X, ...)
```

### 5. Encriptação

- **Em trânsito** — HTTPS sempre, header HSTS, TLS 1.2+, sem cifras fracas (`testssl.sh`, open-source)
- **Em repouso** — DB encriptada (por exemplo `pgcrypto` para colunas sensíveis, ou full-disk)
- **Backups** — encriptados, nunca num bucket público

### 6. Política de privacidade

Se não existe (o `compliance_check` diz em `policy_documents_found`), parte do template `${CLAUDE_PLUGIN_ROOT}/configs/compliance/privacy-policy-template.md` (pt-PT, com o conteúdo dos arts. 13.º e 14.º do RGPD e a CNPD como autoridade de controlo): que dados recolhe e de onde vêm, para quê e com que fundamento, durante quanto tempo, com quem partilha, transferências para fora do EEE, os direitos do titular e como exercê-los, o contacto do responsável. Cada `[[PREENCHER: …]]` é um marcador a substituir ou apagar, e cada `[[CONFIRMAR: …]]` uma afirmação ou um exemplo que só vale para alguns tratamentos (por exemplo, "Não vendemos dados pessoais.") — manter só se for verdade, adaptar ou apagar. Nenhum pode ser publicado (`grep -n "\[\[" politica.md`). **Rever com um advogado antes de publicar.**

## Licenças open-source

1. `compliance_check { project_path: "<project>" }` (se ainda não correu).
2. `license_compatibility { project_path: "<project>" }` — cruza a licença do projeto (`package.json` incluindo `UNLICENSED`, `pyproject.toml`, `composer.json` incluindo `proprietary`, `PackageLicenseExpression` do `.csproj`, ou `LICENSE`) com as das dependências. Sem licença declarada conta como proprietário.

| Tipo                 | Exemplos                  | Compatível com produto comercial fechado?   |
| -------------------- | ------------------------- | ------------------------------------------- |
| Permissiva           | MIT, BSD, ISC, Apache 2.0 | Sim                                         |
| Copyleft fraca       | LGPL, MPL                 | Sim, com cuidado (dynamic linking)          |
| Copyleft forte       | GPL v2/v3, AGPL           | Não (exceto se libertares o teu código)     |
| Não-OSS / comercial  | EULAs próprias            | Verificar cada uma                          |

- 🔴 GPL / AGPL num produto fechado
- 🟡 LGPL — OK como biblioteca dinâmica, problemático em static linking
- 🟢 MIT / Apache / BSD
- `undetermined` (expressões SPDX OR/AND, licenças não reconhecidas) **nunca** é "compatível" — lista-as para decisão humana.

## SBOM

`generate_sbom { project_path: "<project>", format: "cyclonedx-json" }` — ou `format: "spdx-json"`. Syft, com Trivy como fallback; o ficheiro completo fica em `.guardian/reports/sbom-<scan>/` (`file_path` na resposta). Entre releases, `sbom_diff { project_path: "<project>" }`. Útil para responder em minutos a um CVE crítico novo ("usamos a lib X?") e para certificações que o exigem.

## Evidência para auditoria (SOC 2 / ISO 27001 / RGPD)

`compliance_evidence { project_path: "<project>", framework: "gdpr" }` — ou `framework: "soc2"` / `framework: "iso27001"` — gera um documento Markdown a partir do estado acumulado deste projeto: último scan de compliance, resumo de licenças, contagens de CVEs, baseline e supressões. Para o pacote completo de controlos, `/guardian-report soc2`.

Preparação básica que nenhuma tool verifica (checklist):

- [ ] Inventário de subprocessadores (SaaS usados, propósito, DPA assinado)
- [ ] Política de passwords e MFA
- [ ] Backup e disaster recovery testados
- [ ] Logs de acesso preservados ≥ 1 ano
- [ ] Onboarding / offboarding de pessoas
- [ ] Revisões de acesso periódicas

## Frequência

- Privacidade / cookies: a cada release menor
- Licenças: a cada PR que muda dependências
- SBOM: a cada release
- Auditoria completa: anual
