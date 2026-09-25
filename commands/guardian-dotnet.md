---
description: C# / .NET audit — SAST with the SDK analyzers, .NET secrets, EF Core migrations, target frameworks, NuGet CVEs and upgrades. Foco .NET. Foco .NET.
argument-hint: "[project or solution path]"
---

Run the C# / .NET-focused flow, for a project with `*.csproj`, `*.fsproj` or `*.sln` files.

Arguments: $ARGUMENTS

Before step 2, tell the user: `scan_sast`, `deps_audit` and `deps_update_plan` run `dotnet restore --locked-mode`, which **executes the project's own MSBuild** (targets, imported `.props`) and contacts its NuGet feeds. It never creates or rewrites a `packages.lock.json`.

1. `detect_stack { project_path: "<project>" }` — .NET present, frameworks (ASP.NET Core, EF Core), nested projects.
2. `scan_sast { project_path: "<project>" }` — Semgrep (the registry ruleset plus the project's own rules) and, for a root `.csproj` / `.fsproj` / `.sln`, `dotnet build --no-restore` with the SDK security analyzers (plus Security Code Scan when the project references it), read from their SARIF.
3. `bug_hunt { project_path: "<project>" }` — includes the local C# bug pack (`bugfix-cs.yml`).
4. `scan_dotnet_secrets { project_path: "<project>" }` — SQL Server connection strings, Azure Storage / Service Bus keys, NuGet feed credentials and JWT signing keys in `appsettings*.json`, `*.config`, `nuget.config`, `launchSettings.json`.
5. `dotnet_target_framework_check { project_path: "<project>" }` — projects on end-of-life .NET.
6. `dotnet_efcore_audit { project_path: "<project>" }` — dangerous migrations: `DropTable`, `DropColumn`, non-nullable `AlterColumn` without a default, raw SQL with credentials.
7. `deps_audit { project_path: "<project>" }` — Trivy plus `dotnet list package --vulnerable --include-transitive`; then `deps_update_plan { project_path: "<project>", prefer: "security" }` for the ordered upgrades (`runner_failures` names a lock file out of sync versus an unreachable feed).
8. `dotnet_describe_setup {}` — one summary of everything the steps above stored.

Worst first: security, then correctness, then maintenance. When the .NET SDK is missing, say which steps were skipped and offer `install_toolchain { tools: ["dotnet-sdk"], dry_run: true }`.

Respond in the user's language (EN/PT/ES).
