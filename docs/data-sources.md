# Data Sources & Threat Baselines

## 1. Top Packages Baseline (`packages/core/data/top-packages.v1.json`)
- **Version**: `1.0.0`
- **Generation Date**: 2026-03-01
- **Source**: Aggregated from npm public registry high-download download stats and security tracking lists (top 30 foundational libraries frequently targeted by typosquatters).
- **Purpose**: Used by `TyposquatScanner` to detect suspicious name permutations targeting high-reputation packages.

## 2. OSV.dev Vulnerability API
- **Endpoint**: `https://api.osv.dev/v1/query` and `https://api.osv.dev/v1/querybatch`
- **Ecosystem**: `npm`
- **Purpose**: Provides open vulnerability advisories (GHSA, CVE) mapped to direct and transitive dependencies.

## 3. npm Registry Metadata & Tarballs
- **Endpoint**: `https://registry.npmjs.org`
- **Public Keys**: Official registry signing keys and test keypairs for verifying ECDSA package signatures over `name@version:integrity`.
