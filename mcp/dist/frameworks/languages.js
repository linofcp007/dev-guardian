/**
 * The source languages OWASP coverage is judged per (`frameworks/coverage.ts`),
 * and how to recognise them: by the names Semgrep and detect_stack use, and
 * by file extension.
 *
 * Application source languages only. Markup, configuration and shell (HTML,
 * YAML, HCL, Dockerfile, JSON, Bash) are not in the list: a coverage claim
 * is "for every source language of the project, a scanner looked with
 * enough rules", and counting a README's neighbour `.sh` or a static
 * `index.html` as a language would make every category partial for a reason
 * no application-security scan is about. Pure.
 */
export const SOURCE_LANGUAGES = [
    'c',
    'cpp',
    'csharp',
    'dart',
    'elixir',
    'go',
    'java',
    'javascript',
    'kotlin',
    'lua',
    'php',
    'python',
    'ruby',
    'rust',
    'scala',
    'swift',
    'typescript',
];
/**
 * The languages `runners/stackDetect.ts` can report. A detect_stack
 * snapshot's silence about any other language (C#, Swift, C, …) says
 * nothing — it cannot see them.
 */
export const DETECT_STACK_LANGUAGES = [
    'go',
    'java',
    'javascript',
    'kotlin',
    'php',
    'python',
    'ruby',
    'rust',
    'typescript',
];
const ALIASES = {
    c: 'c',
    'c++': 'cpp',
    cpp: 'cpp',
    'c#': 'csharp',
    cs: 'csharp',
    csharp: 'csharp',
    dart: 'dart',
    elixir: 'elixir',
    ex: 'elixir',
    go: 'go',
    golang: 'go',
    java: 'java',
    javascript: 'javascript',
    js: 'javascript',
    kotlin: 'kotlin',
    kt: 'kotlin',
    lua: 'lua',
    php: 'php',
    py: 'python',
    python: 'python',
    rb: 'ruby',
    ruby: 'ruby',
    rs: 'rust',
    rust: 'rust',
    scala: 'scala',
    swift: 'swift',
    ts: 'typescript',
    typescript: 'typescript',
};
/** A language name as Semgrep (`js`, `C#`, `kt`) or detect_stack spells it, or null when it is not a source language. */
export function canonicalLanguage(raw) {
    return ALIASES[raw.trim().toLowerCase()] ?? null;
}
/**
 * `.h` is deliberately absent: a header belongs to C, C++ or Objective-C
 * alike, so the `.c` / `.cpp` files beside it decide, and a C++ project's
 * headers never add C. Objective-C (`.m`, `.mm`) is not in the list at all.
 */
const EXTENSIONS = {
    '.c': 'c',
    '.cc': 'cpp',
    '.cpp': 'cpp',
    '.cxx': 'cpp',
    '.hh': 'cpp',
    '.hpp': 'cpp',
    '.hxx': 'cpp',
    '.cs': 'csharp',
    '.dart': 'dart',
    '.ex': 'elixir',
    '.exs': 'elixir',
    '.go': 'go',
    '.java': 'java',
    '.js': 'javascript',
    '.jsx': 'javascript',
    '.mjs': 'javascript',
    '.cjs': 'javascript',
    '.kt': 'kotlin',
    '.kts': 'kotlin',
    '.lua': 'lua',
    '.php': 'php',
    '.phtml': 'php',
    '.py': 'python',
    '.pyw': 'python',
    '.rb': 'ruby',
    '.rs': 'rust',
    '.scala': 'scala',
    '.swift': 'swift',
    '.ts': 'typescript',
    '.tsx': 'typescript',
    '.mts': 'typescript',
    '.cts': 'typescript',
};
/**
 * Files that are not the product's code even though their extension says a
 * language: build scripts (`build.gradle.kts`), type declarations
 * (`*.d.ts` — no code for a rule to match), minified bundles and generated
 * protobuf / Dart / designer code.
 */
const NOT_PRODUCT_CODE = /(\.gradle\.kts|\.d\.ts|\.min\.js|\.pb\.go|_pb2\.py|_pb2_grpc\.py|\.g\.dart|\.designer\.cs)$/;
/** The source language of a file, by its extension (case-insensitive), or null. */
export function languageOfFile(name) {
    const lower = name.toLowerCase();
    if (NOT_PRODUCT_CODE.test(lower))
        return null;
    const dot = lower.lastIndexOf('.');
    if (dot < 0)
        return null;
    return EXTENSIONS[lower.slice(dot)] ?? null;
}
//# sourceMappingURL=languages.js.map