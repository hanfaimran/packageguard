# Threat Model: Pre-Install npm Package Inspection

## 1. Problem Statement & Scope
Package managers (`npm`, `yarn`, `pnpm`) execute arbitrary lifecycle scripts (`preinstall`, `install`, `postinstall`) under the privileges of the developer machine or CI runner before any application code is tested or run. Attackers exploit this design through:
1. **Compromised Maintainer Accounts**: Adding backdoored postinstall hooks to established packages (e.g., `event-stream`).
2. **Typosquatting & Brandjacking**: Mimicking popular package names (`lodahs`, `cross-env.js`) with immediate payload execution.
3. **Registry Tampering / CDN Poisoning**: Altering distributed tarballs after checksum calculation.
4. **Known Vulnerability Exploitation**: Sneaking vulnerable transitive dependencies into lockfiles.

## 2. PackageGuard Architecture & Security Boundaries
PackageGuard intervenes **strictly before installation**:

```
+--------------------------------------------------------------------------+
|  Package Input (name, ecosystem, version, optional lockfile)             |
+--------------------------------------------------------------------------+
                                     |
                                     v
+--------------------------------------------------------------------------+
|  Zero-Execution Static Collectors (Pure AST / Digest / Heuristics)       |
|  - MetadataScanner: age, maintainers, repo link, script presence         |
|  - VulnScanner: OSV.dev CVSS normalization + lockfile transitive deps    |
|  - IntegrityScanner: SHA-512, ECDSA registry signature, Sigstore best-effort |
|  - TyposquatScanner: Top-30 baseline, Levenshtein, swaps, homoglyphs     |
|  - StaticAnalyzer: AST walk, base64/hex, high entropy, env/credential,  |
|                    outbound endpoints, correlated exfiltration patterns  |
|  - VersionDiffScanner: in-memory tarball diff, maintainers, script jumps |
+--------------------------------------------------------------------------+
                                     |
                                     v
+--------------------------------------------------------------------------+
|  Evidence Normalization & Deduplication (dedupKey + merged sources)      |
+--------------------------------------------------------------------------+
                                     |
                                     v
+--------------------------------------------------------------------------+
|  Risk Engine & Policy Engine (Explainable scoring, hard blocks)          |
+--------------------------------------------------------------------------+
                                     |
                                     v
+--------------------------------------------------------------------------+
|  Explainable Report (JSON / Terminal formatted output)                   |
+--------------------------------------------------------------------------+
```

## 3. Core Security Invariants
- **Zero Execution**: PackageGuard **never** runs package code, executes install scripts, or invokes node on untrusted inputs. Tarballs are decompressed in-memory and parsed as ASTs (`acorn`) or scanned via streaming buffers.
- **Defanged Fixtures**: In synthetic test environments, all malicious artifacts point to `*.invalid` or `127.0.0.1` and never contact public network endpoints.
- **Evidence vs Verdict Separation**: Collectors emit structured `Evidence` only. Verdicts (`Safe`, `Review`, `Block`) and scores are solely calculated by the central Risk & Policy engine.
- **Cryptographic Independence**: Cryptographic verification status (`Verified`, `PartiallyVerified`, `Unverified`) is kept orthogonal to risk score. Missing provenance alone is **never** flagged as malicious.
