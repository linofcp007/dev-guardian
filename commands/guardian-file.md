---
description: Deep scan of a single file or directory. Verifica este ficheiro. Comprueba este archivo.
---

Run a **single-target** Guardian pass against one file (or one directory). Used when the user points at something specific: *"verifica este ficheiro"*, *"check `src/auth.ts`"*, *"comprueba este archivo"*.

The skill should:
1. Resolve the target — explicit `$ARGUMENTS`, or the file currently selected in the editor if the host provides it, or ask.
2. Run `scan_sast` with full rule packs against just that target (no global scan).
3. Run `bug_hunt`, `quality_check`, and the dependency checks that apply to the file's language (e.g. `composer.json` triggers PHP-deps logic).
4. For WordPress / .NET / Docker files, route to the right specialised tool (`scan_wordpress`, `scan_sast` C# branch, `scan_containers`).
5. Show findings inline with file:line refs.

Target file or directory (required for non-editor invocations): $ARGUMENTS
