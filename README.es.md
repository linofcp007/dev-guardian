# dev-guardian

[English](README.md) · [Português (pt-PT)](README.pt-PT.md) · **Español**

Un conjunto open-source de seguridad, detección de bugs, calidad de código, dependencias, cumplimiento normativo, observabilidad y rendimiento para Claude Code y Cowork — y, a través de su servidor MCP, para cualquier host de IA compatible con MCP. Ejecuta escáneres open-source (Semgrep, Trivy, gitleaks, Syft, …), guarda cada resultado en una base de datos SQLite local, para que las baselines, los deltas y las supresiones sobrevivan entre sesiones, y avisa cuando un escáner no se ejecutó en lugar de informar "0 findings". También revisa skills y servidores MCP de terceros, y los paquetes que un agente está a punto de instalar, antes de que lleguen a tu máquina.

Trilingüe: las skills y los comandos responden en inglés, portugués o español, según el idioma en que escribas.

## Qué incluye

- **13 skills** y **10 comandos** slash para Claude Code / Cowork (abajo).
- Un **servidor MCP** con **59 herramientas** y **18 recursos**, en TypeScript sobre `node:sqlite`, ya compilado en el repositorio — referencia completa en [docs/tools.md](docs/tools.md) (en inglés).
- **151 reglas Semgrep en 11 packs** escritas para este proyecto: clases de bugs para siete lenguajes, un pack RGPD, un pack de inventario de rutas para nueve lenguajes y un pack para aplicaciones con LLM (salida del modelo en eval/shell/SQL, código remoto al cargar un modelo, superficie de inyección de prompt, llamadas sin límite de tokens) que `scan_sast` ejecuta — ver [docs/rule-packs.md](docs/rule-packs.md).
- **Hooks de protección** que bloquean comandos de shell catastróficos, revisan paquetes en el momento de instalarlos y avisan cuando se escribe un secreto en un archivo — ver [docs/hooks.md](docs/hooks.md).
- Una **CLI** (`cli/dev-guardian.mjs`) para gates de CI, configuración de hosts, un resumen en terminal y un panel HTML.

## Requisitos

- **Node.js ≥ 22.13.** La base de datos es el `node:sqlite` integrado en Node, sin ningún flag. Con un Node más antiguo el servidor termina con `dev-guardian requires Node.js >= 22.13 (node:sqlite)`.
- **git.**
- **Los escáneres que quieras usar**, instalados aparte. `check_toolchain` indica cuáles están presentes (y marca el Trivy comprometido 0.69.4–0.69.6); `install_toolchain` o `/guardian-init` instalan el resto. Un escáner que falta se informa como hueco de cobertura, nunca como resultado limpio.
- **Opcional: Docker.** Sin un `semgrep` nativo, `scan_sast` y `map_attack_surface` recurren a la imagen `semgrep/semgrep`.
- **Windows:** todos los escaneos se ejecutan de forma nativa, sin shell. Solo hace falta un bash para el informe de estado inicial de `init_project` y para el recurso a WSL de `install_toolchain` cuando no hay winget, scoop ni choco. dev-guardian busca primero Git Bash, luego WSL y luego cualquier `bash` en el `PATH`.

No hace falta `npm install`: `mcp/dist/server.js` está en el repositorio como un bundle autónomo. Solo los comandos `scan` y `baseline update` de la CLI necesitan `npm ci --omit=dev` en `mcp/`, una vez, para sus paquetes de runtime.

## Inicio rápido (Claude Code)

```text
/plugin marketplace add https://github.com/linofcp007/dev-guardian
/plugin install dev-guardian@dev-guardian
```

Después, en tu proyecto:

```text
/guardian-init        detecta el stack, instala los escáneres, escribe las configuraciones y los hooks de pre-commit
/guardian-scan        escaneo de seguridad completo (o --staged, --branch, --since …)
/guardian-status      estado del proyecto en una sola pantalla
```

Desde un clon local: `claude --plugin-dir /ruta/a/dev-guardian` para una sesión, o `/plugin marketplace add /ruta/a/dev-guardian` para instalarlo. Todas las skills responden también a lenguaje natural — "audita el proyecto", "¿es seguro lanzarlo?", "¿hay agujeros de seguridad?".

## Comandos slash

| Comando | Modos | Qué hace |
| --- | --- | --- |
| `/guardian-scan` | ninguno, `--staged`, `--uncommitted`, `--unpushed`, `--branch [base]`, `--since <ref>`, `--incoming`, rutas | Escaneo de seguridad del proyecto entero, o solo de lo que cambió |
| `/guardian-fix` | pista, fingerprint, `--pr [--apply]`, `--verify` | Encuentra y corrige bugs, abre PRs de corrección verificados, demuestra una corrección con un nuevo escaneo |
| `/guardian-report` | `exec`, `handoff`, `trend`, `debt`, `changelog`, `soc2` | Informes a partir del historial de escaneos |
| `/guardian-incident` | `panic`, `leak`, `rollback`, `postmortem` | Respuesta a incidentes |
| `/guardian-release` | `predeploy`, `prerelease` | Gates de go / no-go |
| `/guardian-status` | enfoque opcional (p. ej. "solo seguridad") | Último escaneo, deltas, baseline, supresiones a punto de caducar |
| `/guardian-infra` | `docker`, `iac` | Dockerfile, imagen, compose, Terraform, Kubernetes, CloudFormation, Helm |
| `/guardian-wp` | ruta de la instalación o URL del sitio | Auditoría de WordPress |
| `/guardian-dotnet` | ruta del proyecto o de la solución | Auditoría de C# / .NET |
| `/g` | lo que quieres revisar | Atajo de la skill `guardian` (el router) |

La versión 2.0.0 tenía 48; el `CHANGELOG.md` indica, para cada nombre antiguo, cuál lo sustituye.

## Skills

| Skill | Para |
| --- | --- |
| `/guardian` | Router: elige el comando o la skill adecuados |
| `/guardian-security` | SAST, secretos, CVEs de dependencias, IaC, DAST y alcanzabilidad, con triaje |
| `/guardian-bugfix` | Bugs de implementación, encontrados y corregidos con método |
| `/guardian-init` | Primer uso en un proyecto: toolchain, configuraciones, pre-commit |
| `/guardian-review` | Revisión de nivel sénior antes de un PR, merge o despliegue |
| `/guardian-deps` | Auditoría de CVEs, plan y PRs de actualización, revisión de instalaciones, licencias, SBOM |
| `/guardian-quality` | Duplicación, complejidad, deuda técnica, `.guardian/budgets.yml` |
| `/guardian-compliance` | RGPD, licencias, SBOM, evidencias de auditoría, plantillas de banner de cookies y de política de privacidad |
| `/guardian-observability` | Logging estructurado y métricas |
| `/guardian-performance` | Lighthouse, k6, presupuestos de rendimiento |
| `/guardian-grill` | Te interroga sobre las decisiones de un diff antes del merge |
| `/guardian-improve` | Convierte la deuda técnica medida en specs de mejora |
| `/guardian-scanskill` | Revisa una skill, servidor MCP o agente de terceros antes de instalarlo |

## El servidor MCP

| Área | Herramientas |
| --- | --- |
| Escaneos de seguridad | `security_scan_full`, `scan_sast`, `scan_secrets`, `scan_deps`, `scan_containers`, `scan_iac`, `review_pr` |
| Bugs y calidad | `bug_hunt`, `quality_check`, `suggest_fix`, `create_fix_pr` |
| Dependencias y cadena de suministro | `deps_audit`, `deps_update_plan`, `vet_packages`, `generate_sbom`, `sbom_diff`, `export_vex`, `license_compatibility`, `scan_skill`, `audit_agent_config`, `audit_mcp_tools` |
| Superficie de ataque | `map_attack_surface`, `scan_dast`, `validate_finding` |
| Historial y triaje | `diff_scans`, `set_baseline`, `suppress_finding`, `regression_alert`, `risk_score`, `prioritize_findings`, `triage_findings`, `health_status` |
| Informes | `audit_executive`, `report_export`, `compliance_check`, `compliance_evidence`, `create_github_issues` |
| Configuración y operación | `detect_stack`, `check_toolchain`, `install_toolchain`, `init_project`, `precommit_install`, `register_custom_rules`, `observability_setup`, `perf_check` |
| WordPress | `scan_wordpress`, `wp_audit`, `wp_vuln_check`, `wp_vuln_check_source`, `wp_plugin_check`, `wp_cron_audit`, `wp_rest_audit`, `wp_recommend_hardening`, `wp_describe_setup`, `bulk_audit_wordpress_sites` |
| C# / .NET | `scan_dotnet_secrets`, `dotnet_target_framework_check`, `dotnet_efcore_audit`, `dotnet_describe_setup` |

Los recursos (`guardian://scans/latest`, `guardian://findings/open`, `guardian://cves/active`, `guardian://surface/latest`, …) sirven los resultados guardados en JSON. Todo se guarda en `.guardian/guardian.db`; el servidor mantiene `.guardian/` fuera de git, salvo `.guardian/baseline.json`, que la CI necesita en el repositorio.

## Qué recibe cada stack

| Stack | Detectado | Reglas de bugs (`bug_hunt`) | Rutas (`map_attack_surface`) | CVEs de dependencias | Alcanzabilidad (`validate_finding`) |
| --- | --- | --- | --- | --- | --- |
| JavaScript / TypeScript | sí | 13 reglas | Express, NestJS | Trivy, `npm audit` | alcanzable / inalcanzable |
| Python | sí | 10 reglas | Flask, FastAPI, Django | Trivy, `pip-audit` | alcanzable / inalcanzable |
| Go | sí | 9 reglas | net/http, gin, chi | Trivy | alcanzable / inalcanzable |
| Rust | sí | 1 regla (sleep bloqueante dentro de una `async fn`) | actix-web | Trivy | alcanzable / inalcanzable |
| Java | sí | 7 reglas | Spring | Trivy (Maven; Gradle solo con `gradle.lockfile`) | solo alcanzable / desconocido |
| C# / .NET | sí | 11 reglas | ASP.NET Core | Trivy, `dotnet list package --vulnerable` | solo alcanzable / desconocido |
| PHP | sí, también sin `composer.json` | 6 reglas | Laravel | Trivy (`composer.lock`) | solo alcanzable / desconocido |
| WordPress | sí, con WooCommerce y Kadence | las reglas PHP, más `p/wordpress` en `scan_wordpress` | rutas REST | WPScan (URL en vivo), feed de Wordfence (desde el código) | como PHP |
| Ruby | sí | ninguna — usa RuboCop | rutas estilo Rails | Trivy (`Gemfile.lock`) | solo alcanzable / desconocido |
| Kotlin | **solo detección** | — | — | — | — |

Más allá de la tabla, `scan_sast` ejecuta el ruleset del registry de Semgrep (`--config=auto`), que elige reglas para los lenguajes que encuentre — Kotlin incluido — y gitleaks busca secretos en cualquier proyecto. Contenedores e IaC (Dockerfile, imágenes, compose, Terraform, Kubernetes, CloudFormation, Helm, workflows de GitHub Actions) quedan cubiertos por `scan_containers` y `scan_iac`; en una imagen, `scan_containers` usa además cosign para ver si está firmada y tiene procedencia SLSA firmada, y verifica quién la firmó cuando indicas el firmante. "Solo alcanzable / desconocido" significa que la herramienta nunca afirma que un código es inalcanzable en un lenguaje que resuelve el código en tiempo de ejecución (autoload, anotaciones, contenedores de DI). .NET tiene además cuatro herramientas propias y WordPress diez. Trivy lee un lock file de Gradle en cualquier proyecto, Kotlin incluido, y un build de Gradle que no pudo leer se señala como hueco de cobertura; para Kotlin no hay reglas de bugs ni extracción de rutas.

**Gradle y Python necesitan un lock file para Trivy.** Trivy solo lee las dependencias de Gradle desde `gradle.lockfile`, y las de Python desde `poetry.lock`, `uv.lock`, `Pipfile.lock` o un `requirements.txt` con versiones fijadas. Un `build.gradle` / `build.gradle.kts`, `pyproject.toml`, `setup.py` / `setup.cfg`, `Pipfile` o `requirements*.txt` que no pudo leer se informa como hueco de cobertura (`trivy:gradle`, `trivy:python`, o `trivy` omitido cuando no leyó nada más), nunca como un escaneo limpio. Vale para un manifiesto en cualquier punto del árbol — incluido un `web/package.json` junto a un lock file en la raíz; solo un miembro de un workspace queda cubierto por el lock de la raíz — y para un `go.mod` que Trivy no pudo interpretar (`trivy:go`). Para cerrarlo, genera el lock file. En Gradle, activa primero `dependencyLocking { lockAllConfigurations() }` en el build — sin ello, `gradle dependencies --write-locks` no escribe nada — y solo después ejecuta ese comando. En Python, ejecuta `poetry lock`, `uv lock` o `pipenv lock`, o fija la versión de cada dependencia en `requirements.txt`.

## Hooks de protección

Se cargan automáticamente con el plugin, sin dependencias y en fail-open:

- **SessionStart** — un resumen breve de la postura de seguridad.
- **PostToolUse** en escrituras — avisa, con una vista previa enmascarada, cuando se escribe un secreto.
- **PreToolUse** en Bash y PowerShell — bloquea comandos catastróficos (`rm -rf /`, `curl … | sh`, `iwr … | iex`, escrituras directas en disco, fork bombs), avisa en los arriesgados y revisa los paquetes antes de que `npm`, `pnpm`, `yarn`, `bun`, `pip`, `uv`, `poetry`, `composer` o `dotnet add package` los instalen: un paquete malicioso se bloquea; uno inexistente solo se bloquea en un comando de instalación simple y único.
- **PreToolUse** en escrituras — impide que un asistente edite la propia configuración de los hooks; opcionalmente bloquea la escritura de un token de un proveedor.

El `.guardian/hooks.config.json` de un proyecto solo puede hacerlos más estrictos; desactivar uno exige la configuración del usuario o una variable de entorno.

Detalles, configuración y formas de desactivarlos: [docs/hooks.md](docs/hooks.md). Los mismos detectores se ejecutan desde la terminal con `node cli/dev-guardian.mjs check --file <ruta>` o `--bash "<comando>"`.

## Otros hosts de IA

Cursor, Windsurf, GitHub Copilot, Codex CLI, Gemini CLI, Cline y Claude Desktop reciben el servidor MCP y un archivo de reglas (sin skills, comandos ni hooks). Clona una vez y después ejecuta la CLI **por su ruta absoluta** desde tu proyecto:

```text
git clone --depth 1 --branch v3.0.0 https://github.com/linofcp007/dev-guardian.git ~/tools/dev-guardian
node ~/tools/dev-guardian/cli/dev-guardian.mjs mcp-config cursor --write
node ~/tools/dev-guardian/cli/dev-guardian.mjs mcp-config all --write --update-mcp
```

El clon de arriba fija la 3.0.0; para seguir una versión posterior, clona su etiqueta `vX.Y.Z`. `--update-mcp`, `--global` y `ci-init` necesitan la 3.0.0 o posterior — 2.0.0 además escribe las configuraciones globales de Windsurf y Claude Desktop con `mcp-config all --write`. La CLI rellena las rutas absolutas, fusiona en lugar de sobrescribir y solo gestiona un bloque delimitado dentro de archivos como `AGENTS.md`; `--update-mcp` actualiza una entrada desfasada. Rutas por host y fragmentos manuales: [docs/hosts.md](docs/hosts.md).

## CI

```text
npm ci --omit=dev --prefix ~/tools/dev-guardian/mcp                                  # una vez: paquetes de runtime de scan
node ~/tools/dev-guardian/cli/dev-guardian.mjs ci-init github --write                # también gitlab, bitbucket
node ~/tools/dev-guardian/cli/dev-guardian.mjs baseline update --project .           # haz commit de .guardian/baseline.json
node ~/tools/dev-guardian/cli/dev-guardian.mjs scan --project . --fail-on high --sarif results.sarif
```

`ci-init` genera un pipeline con cada action fijada por SHA de commit y cada escáner por versión y checksum. `scan` termina con 0 si pasa, 1 cuando un finding nuevo respecto a la baseline alcanza `--fail-on`, **2 cuando un escáner no se ejecutó** (nunca lo leas como aprobado) y 3 ante un error de uso. Ver [docs/ci.md](docs/ci.md). Ejecútalos desde tu proyecto, con la ruta de tu clon (la copia del propio plugin también sirve). Para una vista local: `status` y `dashboard` (una página HTML autónoma, sin red).

## Privacidad y red

dev-guardian no envía telemetría propia. Algunas herramientas sí acceden a la red — el modo registry de Semgrep (que envía métricas de uso a Semgrep Inc.; `local_only: true` lo evita), la base de datos de Trivy, los feeds NuGet de un proyecto .NET (`scan_sast` lo restaura y lo compila, con o sin `local_only`), OSV, los registros de paquetes, CISA KEV / FIRST EPSS, Wordfence y la verificación de secretos en vivo, que es opcional. La lista completa, por herramienta, está en [SECURITY.md](SECURITY.md). `GUARDIAN_OFFLINE=1` desactiva las consultas que dev-guardian hace por su cuenta (inteligencia de amenazas, revisión de paquetes, verificación de secretos en vivo, el feed de Wordfence); todas las variables de entorno están en [docs/env.md](docs/env.md).

## Solución de problemas

**El servidor MCP no conecta.** `/mcp` en Claude Code muestra el estado del servidor. Claude Code guarda el stderr de cada servidor en su directorio de caché: `%LOCALAPPDATA%\claude-cli-nodejs\Cache\<proyecto>\mcp-logs-<servidor>\` en Windows (el del plugin es `mcp-logs-plugin-dev-guardian-dev-guardian`) y — por la misma convención, no verificado aquí — `~/.cache/claude-cli-nodejs/…` en Linux y `~/Library/Caches/claude-cli-nodejs/…` en macOS. Las causas habituales:

- Node anterior a 22.13 (ver Requisitos).
- Un `.mcp.json` de proyecto que usa `${CLAUDE_PROJECT_DIR}`: Claude Code no expande esa variable ahí y `node` recibe el texto literal. Usa una ruta relativa; los servidores de proyecto arrancan en la raíz del proyecto.

**`no_bash_shell`.** Solo la instalación por defecto de `install_toolchain` en Linux y macOS necesita bash, además del informe de estado de `init_project`. En Windows, instala Git for Windows. Desde PowerShell, `bash` puede apuntar al stub de WSL en lugar de Git Bash; dev-guardian busca Git Bash primero por su cuenta, pero un comando que escribas tú puede no hacerlo.

**Cobertura `none` o `partial`, o `scan` termina con 2.** Un escáner faltó, falló o no analizó nada. `tools_run` y `missing_tools` en la respuesta dicen cuál; `check_toolchain` muestra lo que está instalado. Arréglalo y vuelve a ejecutar — un escaneo con huecos nunca se sirve desde la caché.

**`install_toolchain` con `elevation_allowed: true` falla con "sudo: a terminal is required to read the password".** Los pasos de instalación se ejecutan desacoplados, sin terminal, así que en Linux y macOS la elevación solo funciona con sudo sin contraseña para esos comandos. Si no, ejecuta tú los comandos listados en `requires_elevation`. El SDK de .NET nunca se instala automáticamente.

**Semgrep envía métricas.** `scan_sast` por defecto usa `--config=auto`, que Semgrep solo permite con las métricas activadas. Pasa `local_only: true` (o `--local-only` en la CLI) para mantener Semgrep en local: solo reglas en disco — las del proyecto y los paquetes del plugin (el paquete para aplicaciones LLM sigue ejecutándose) — con `--metrics=off` y sin descargas del registro. No significa "nada sale de la máquina": Trivy sigue descargando su base de datos de vulnerabilidades y un proyecto .NET se sigue restaurando desde sus feeds de NuGet ([SECURITY.md](SECURITY.md#network-egress)). La comprobación de versión del propio Semgrep está desactivada en todas las ejecuciones.

## Estructura del repositorio

```text
.claude-plugin/   plugin.json + marketplace.json
commands/         los 10 comandos slash
skills/           las 13 skills
hooks/            hooks.json + guardian-hook.mjs
cli/              dev-guardian.mjs (mcp-config, check, scan, baseline, ci-init, status, dashboard)
mcp/              el servidor MCP: src/, test/, dist/ (en el repositorio)
configs/          packs Semgrep, plantillas de CI, configuraciones de gitleaks/Renovate/pre-commit, plantillas de cumplimiento
host-rules/       plantillas de reglas para otros hosts
docs/             herramientas, packs de reglas, hooks, CI, hosts, entorno (en inglés)
scripts/          install-linux.sh, install-macos.sh, initial-scan.sh
```

Contribuir: [CONTRIBUTING.md](CONTRIBUTING.md) y [CLAUDE.md](CLAUDE.md). Informar de vulnerabilidades: [SECURITY.md](SECURITY.md).

## Licencia

MIT. Carlos Pereira · [prodigitalkey.com](https://prodigitalkey.com)
