# Architecture

Dependency Guardian is a runtime-dependency-free TypeScript CLI built for Node.js 22+.

- `src/parser.ts`: reads installed npm lockfile v2/v3 entries, including nested installations and aliases.
- `src/osv.ts`: batches package/version queries, handles pagination and retrieves full OSV advisories.
- `src/scanner.ts`: merges findings, classifies supported CVSS scores, and preserves install paths.
- `src/report.ts`: renders terminal, JSON-compatible, Markdown and SARIF output.
- `src/cli.ts`: implements policy thresholds, filtering and predictable exit codes.

No server or database is required. OSV receives package metadata (names and versions), never source files.

Future versions may introduce a local SQLite advisory cache, more package-manager parsers, a web dashboard and a hosted GitHub App.
