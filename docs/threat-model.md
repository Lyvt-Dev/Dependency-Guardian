# Threat model

## Protected assets

Developer workstation integrity, CI credentials, private dependency metadata, reliable vulnerability findings and the OSV availability signal.

## Threats and mitigations

- Malicious lockfiles: bounded file size, supported version checks and no execution of project scripts.
- Registry SSRF: lockfile URLs are never fetched; only the fixed OSV HTTPS endpoint is used.
- Partial OSV responses: validate result cardinality, hydrate advisory details, fail closed on lookup errors.
- Dependency confusion: use installed lockfile versions, not unsolved semver ranges.
- Missing severity: report UNKNOWN rather than silently downgrading.
- CI secrets: workflows use minimal read permissions.

## Known limitations

Large JSON objects may still require significant memory within the 25 MiB file limit. Binary SBOMs and non-npm ecosystems are unsupported. The scanner does not determine whether an exploit is reachable, verify package integrity cryptographically, or run malicious-package analysis.
