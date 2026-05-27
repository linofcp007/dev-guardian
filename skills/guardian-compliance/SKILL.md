---
name: guardian-compliance
description: Compliance check — GDPR/RGPD, OSS licenses, SBOM (Syft), privacy policy scaffolding. EN triggers — use when the user says "guardian compliance", "GDPR", "personal data handling", "licenses", "can you check the licenses?", "I need an SBOM", "cookie consent", "privacy policy", "terms of use", "data retention", "anonymization", "DPO", "right to be forgotten", "SOC 2 prep", "ISO 27001". PT triggers — usa quando disserem "guardian compliance", "GDPR", "RGPD", "tratamento de dados pessoais", "licenças", "podes verificar as licenças?", "preciso de SBOM", "cookie consent", "privacy policy", "termos de utilização", "data retention", "anonimização", "DPO", "right to be forgotten", "SOC 2 prep", "ISO 27001". ES triggers — úsala cuando digan "guardian compliance", "RGPD", "LOPD", "tratamiento de datos personales", "licencias", "¿puedes revisar las licencias?", "necesito un SBOM", "cookie consent", "política de privacidad", "términos de uso", "retención de datos", "anonimización", "DPO", "derecho al olvido", "preparación SOC 2", "ISO 27001". Trilingual EN/PT/ES — respond in the user's language.
---

# Guardian Compliance

Compliance check pragmático para projetos web/SaaS. Foca em GDPR (utilizadores na UE), licenças open-source, e prontidão básica para auditorias.

> Esta skill orienta tecnicamente. **Não substitui aconselhamento legal.** Para questões específicas de direito português/europeu, sugerir a skill `advogado-pt` se disponível.

## GDPR / RGPD — checklist técnica

Para apps que tratam dados de utilizadores na UE:

### 1. Mapeamento de dados pessoais

Identifica que dados pessoais a app guarda. Procura no código:

```bash
# Padrões comuns
grep -rE "(email|phone|address|name|cpf|nif|birthday|ip|cookie)" --include="*.{ts,js,py,php}"
```

Lista no formato:

```
| Dado          | Onde guardado | Quem acede | Retenção | Base legal       |
| ------------- | ------------- | ---------- | -------- | ---------------- |
| Email         | users table   | App+admin  | Indef.   | Contrato         |
| IP            | logs Loki     | Admin      | 90 dias  | Legítimo interesse |
```

### 2. Cookies e tracking

Verifica:
- Há cookie banner antes de set cookies não-essenciais?
- Há opt-out para analytics? (Plausible/Umami são GDPR-friendly por design, sem banner)
- Há third-party scripts (Google Analytics, Facebook Pixel)?
  - GA4 não é trivialmente GDPR-compliant — considera Plausible/Umami/PostHog self-hosted
- Cookies essenciais (auth) podem usar `HttpOnly; Secure; SameSite=Strict`

Templates em `${CLAUDE_PLUGIN_ROOT}/configs/compliance/cookie-banner/` (HTML+JS minimal sem dependências).

### 3. Direitos do utilizador

A app suporta?
- **Acesso** — pode o utilizador descarregar os seus dados? (endpoint `/me/export`)
- **Retificação** — pode atualizar perfil?
- **Apagamento** — endpoint `/me/delete` que apaga ou anonimiza?
- **Portabilidade** — export em formato standard (JSON/CSV)?
- **Oposição** — pode desativar marketing? Opt-out de profiling?

Para cada um em falta, propõe endpoint + UI mínimos.

### 4. Logs e PII

Verifica que logs **não** guardam:
- Passwords (mesmo hashed em logs é mau)
- Tokens completos (mascara: `tok_abc...xyz`)
- Body de requests com PII
- IPs completos (anonimiza: 192.168.1.0)

Usa Semgrep para procurar:

```yaml
rules:
  - id: log-pii
    patterns:
      - pattern-either:
          - pattern: logger.$LEVEL(..., password=..., ...)
          - pattern: logger.$LEVEL(..., token=..., ...)
    message: Possível PII/secret a ir para logs
```

### 5. Encryption

- **Em trânsito** — HTTPS sempre, HSTS header
- **Em repouso** — DB encriptada (Postgres `pgcrypto` para colunas sensíveis; ou full-disk)
- **Backups** — encriptados (não em S3 público!)

Verifica configs:
- TLS 1.2+ no servidor
- Sem cifras fracas (testar com `testssl.sh` open-source)

### 6. Privacy policy

Se não existe, gera template em `${CLAUDE_PLUGIN_ROOT}/configs/compliance/privacy-policy-template.md` com:
- Que dados recolhe
- Para quê
- Quanto tempo mantém
- Com quem partilha
- Direitos do utilizador e como exercer
- Contacto do controlador

Avisa: **rever com advogado antes de publicar**.

## Licenças open-source

### Scan

```bash
# Node
npx license-checker --json --production > .guardian/licenses.json

# Python
pip-licenses --format=json --output-file .guardian/licenses.json --with-license-file

# PHP
composer licenses --format=json > .guardian/licenses.json

# Go
go-licenses report ./... > .guardian/licenses.csv
```

### Análise

Para cada dependência, classifica:

| Tipo                | Exemplos        | Compat. com projeto comercial proprietário? |
| ------------------- | --------------- | -------------------------------------------- |
| Permissive          | MIT, BSD, ISC, Apache 2.0 | ✅ Sim                              |
| Weak copyleft       | LGPL, MPL       | ⚠️ Sim com cuidado (dynamic linking)        |
| Strong copyleft     | GPL v2/v3, AGPL | ❌ Não (excepto se libertares o teu)        |
| Non-OSS / commercial| Custom EULAs    | Verificar cada um                            |

Sinaliza imediatamente:
- 🔴 GPL/AGPL detetada — incompatível com produto fechado
- 🟡 LGPL — OK se usado como dynamic lib, problemático se static link
- 🟢 MIT/Apache/BSD — OK

Output em formato lista clara, com link ao licença e package.

## SBOM (Software Bill of Materials)

Útil para:
- Resposta rápida a CVE críticos (sei se uso a lib X em 30 segundos)
- Compliance (algumas certificações exigem)
- Auditoria de supply chain

Gera com Syft:

```bash
syft . -o cyclonedx-json > sbom.json
syft . -o spdx-json > sbom-spdx.json   # SPDX format
syft . -o table                         # human readable
```

Inclui no CI para regenerar a cada release.

## SOC 2 / ISO 27001 — preparação básica

Não é objetivo desta skill conduzir auditoria. Mas pode preparar o terreno:

- [ ] Inventário de subprocessadores (lista de SaaS usados, propósito, DPA assinado)
- [ ] Política de passwords e MFA
- [ ] Backup e disaster recovery testados
- [ ] Logs de acesso preservados ≥1 ano
- [ ] Process de onboarding/offboarding de pessoas
- [ ] Revisões de acesso periódicas

Para cada item, propõe o mínimo viável (template em Markdown) e marca como "rever em auditoria".

## Cookie banner mínimo

Template open-source pronto a colar (sem dependências externas, GDPR-friendly):

```html
<!-- ${CLAUDE_PLUGIN_ROOT}/configs/compliance/cookie-banner/banner.html -->
```

Comportamento:
- Mostra na primeira visita
- 3 opções: Aceitar todos · Só essenciais · Configurar
- Bloqueia tracking até decisão (não set scripts)
- Decisão persiste em localStorage por 6 meses
- Link permanente "Cookie settings" no footer

## Frequência

- Privacy/cookies review: **a cada release menor**
- Licença scan: **a cada PR que muda dependências**
- SBOM regen: **a cada release**
- Audit completa: **anual**

## Output

Sumário em `.guardian/reports/compliance-<timestamp>.md` com checklist completa, status de cada item, ações pendentes.
