<div align="center">

# 🛡️ Dependency Guardian

**Know what your dependencies are hiding.**

A lightweight, open-source npm security scanner powered by OSV. Audit your project's known dependency vulnerabilities without uploading source code or using a cloud account.

![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?logo=typescript&logoColor=white) ![Node.js](https://img.shields.io/badge/Node.js-22%2B-339933?logo=nodedotjs&logoColor=white) ![License](https://img.shields.io/badge/license-Apache--2.0-blue) ![Version](https://img.shields.io/badge/version-0.2.0-green)

</div>

## ✨ Features

- **npm lockfile v2/v3 scanning:** direct, transitive, nested dependencies and npm aliases.
- **OSV intelligence:** batched vulnerability queries, pagination and advisory details.
- **Reports:** colored-style terminal output, JSON, Markdown and SARIF 2.1.0.
- **Security policies:** severity threshold, suppression by advisory ID, exclude dev dependencies, and fail on unknown severity.
- **CI-friendly:** exit 0 for passed, 1 for policy failures, 2 for incomplete scans/errors.
- **Low attack surface:** scans lockfiles without running project install scripts; no runtime dependencies.

## 🚀 Quick start

Requires **Node.js 22+** and network access to `api.osv.dev`.

```bash
git clone https://github.com/Lyvt-Dev/Dependency-Guardian.git
cd Dependency-Guardian
npm install
npm run build
node dist/cli.js scan /path/to/project --severity high
```

### CLI options

```bash
node dist/cli.js scan .
node dist/cli.js scan . --exclude-dev
node dist/cli.js scan . --ignore GHSA-example-1234
node dist/cli.js scan . --fail-on-unknown
node dist/cli.js scan . --json --output report.json
node dist/cli.js scan . --markdown --output report.md
node dist/cli.js scan . --sarif --output report.sarif
node dist/cli.js doctor
node dist/cli.js explain GHSA-example-1234
```

| Exit code | Meaning |
| --- | --- |
| `0` | Completed scan and no findings at configured threshold |
| `1` | Vulnerability policy violated |
| `2` | Scanner error or incomplete vulnerability lookup |

> **Privacy:** OSV receives package names and versions; source code is not uploaded. Evaluate private package metadata before scanning. Unsupported package managers and offline mode are not yet implemented.

## 🏗 Architecture

```text
package-lock.json
       │
       ▼
 npm lockfile parser
       │
       ▼
 name/version deduplication
       │
       ▼
 OSV batch queries + pagination
       │
       ▼
 advisory details + severity scoring
       │
       ▼
 terminal / JSON / Markdown / SARIF
```

## 🧪 Quality

```bash
npm test
npm run check
```

Tests cover parsing, aliases, API responses, severity, deduplication, failed lookups, filtering and reporting. OSV Live API access is required for real-world online scans.

## 🛡️ Security considerations

This tool checks **known advisories**, not whether a package is malware or whether an exploit is reachable. CVSS v4 vector scoring, offline caching, upgrade automation and multi-ecosystem support are not included in v0.2.0. Severity may be UNKNOWN. Incomplete scans are **never treated as clean**.

See [Security Policy](SECURITY.md), [Architecture](docs/architecture.md), [Threat Model](docs/threat-model.md) and [Contributing](CONTRIBUTING.md).

## 🗺 Roadmap

- [x] npm lockfile parser and OSV integration
- [x] CLI, JSON, Markdown and SARIF output
- [x] CI exit codes and filtering
- [ ] Published GitHub Action and npm CLI
- [ ] Persistent cache, offline mode, dependency graph improvements
- [ ] Auto-fix PRs, provenance signals and package-manager support
- [ ] Web dashboard and scan history

## 🤝 Contributing

Contributions and issues are welcome. Please report security problems using [SECURITY.md](SECURITY.md).

**License:** Apache-2.0.

<div align="center"><sub>Built for developers who want transparency over their software supply chain.</sub></div>
