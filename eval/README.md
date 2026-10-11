# Evaluation Lab (`/eval`)

## Overview
The Evaluation Lab contains reproducible, completely inert and defanged test fixtures modeled on real-world supply-chain compromises (including the classic `event-stream` attack pattern), a mock local registry with cryptographic signatures, and a benchmark suite evaluating precision, recall, and false-positive rates.

## Fixture Catalog
All fixtures are synthesized dynamically by `eval/src/fixtures/generator.ts`:
1. `clean-pkg@1.0.0`: Ground truth **benign**. Clean utility module.
2. `benign-tool@1.0.0`: Ground truth **benign**. Hard negative testing false positives (legitimate use of `child_process.execSync` and `process.env.DEBUG`).
3. `event-stream-lite@1.0.0`: Ground truth **benign**. Clean baseline version of stream utility.
4. `event-stream-lite@1.0.1`: Ground truth **malicious**. Adds a `postinstall` script, a new maintainer (`right9ctrl`), and an obfuscated base64 payload exfiltrating credentials to `http://exfil.invalid`.
5. `vulnerable-pkg@1.0.0`: Ground truth **malicious**. Vulnerable version with critical OSV advisory.
6. `lodahs@1.0.0`: Ground truth **malicious**. Typosquat variation of `lodash` with install scripts and newly published timestamp.
7. `tampered-pkg@1.0.0`: Ground truth **malicious**. Tampered package whose delivered tarball bytes differ cryptographically from published registry hash.

## Running the Benchmark & Demo
```bash
# Run benchmark confusion matrix & generate report.json / report.md
npm --workspace=eval run benchmark

# Run the live interactive terminal demo scanning event-stream-lite@1.0.1
npm run demo
```

## Limitations & Disclaimer
> [!NOTE]
> Synthetic fixtures do not establish real-world detection accuracy against active production threats. They serve to validate scanner invariants, correlation rules, and regression protection in controlled testing environments.
