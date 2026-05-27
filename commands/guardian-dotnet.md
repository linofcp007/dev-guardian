---
description: C# / .NET-focused audit (SAST + secrets + EF Core + target frameworks). Foco .NET. Foco .NET.
---

Run the **C# / .NET-focused** Guardian flow. Use when the project has `*.csproj` / `*.sln` / `*.fsproj` files.

The skill should invoke, in order:
1. `detect_stack` — confirm .NET stack version, frameworks (ASP.NET Core, EF Core), central package management.
2. `scan_sast` — runs Semgrep with `p/csharp` + parses `security-code-scan` (SCS####) warnings if the analyzer is opted-in via NuGet.
3. `scan_dotnet_secrets` — looks for hardcoded connection strings, JWT signing keys, `appsettings.json` leaks, user-secrets misuse.
4. `dotnet_target_framework_check` — flag projects still targeting EOL .NET versions.
5. `dotnet_efcore_audit` — N+1 queries, missing async, raw SQL injection risk, lazy-loading misuse.
6. `deps_update_plan` (dotnet branch) — runs `dotnet list package --outdated`, classifies upgrades, marks security ones from active CVEs.

Surface the worst findings first (security > correctness > maintenance). If `dotnet` SDK is missing, say so and offer `install_toolchain` with `dotnet-sdk`.

Project path or solution hint (optional): $ARGUMENTS
