# PackageGuard Benchmark Evaluation Report

## 1. Summary Metrics
- **Total Evaluated Packages**: 7
- **True Positives (TP)**: 4
- **False Positives (FP)**: 0
- **True Negatives (TN)**: 3
- **False Negatives (FN)**: 0
- **Precision**: 100.0%
- **Recall / Detection Rate**: 100.0%
- **F1 Score**: 1.000
- **False Positive Rate (FPR)**: 0.0%

## 2. Per-Package Evaluation Matrix
| Package | Version | Ground Truth | Verdict | Score | Verification | Classification |
|---|---|---|---|---|---|---|
| clean-pkg | 1.0.0 | benign | **Safe** | 100 | PartiallyVerified | TN |
| benign-tool | 1.0.0 | benign | **Safe** | 100 | PartiallyVerified | TN |
| event-stream-lite | 1.0.0 | benign | **Safe** | 95 | PartiallyVerified | TN |
| event-stream-lite | 1.0.1 | malicious | **Review** | 68 | PartiallyVerified | TP |
| vulnerable-pkg | 1.0.0 | malicious | **Block** | 62 | PartiallyVerified | TP |
| lodahs | 1.0.0 | malicious | **Review** | 65 | PartiallyVerified | TP |
| tampered-pkg | 1.0.0 | malicious | **Block** | 60 | Unverified | TP |

## 3. Limitations & Real-World Caveats
> [!IMPORTANT]
> **Evaluation Limitations Disclaimer**:
> This benchmark operates against synthetic, defanged test fixtures engineered to model real-world attack vectors (e.g., event-stream supply chain injection, typosquatting, metadata manipulation, hash tampering, and known CVEs).
> **Synthetic fixtures do not establish real-world detection accuracy** in production ecosystems. Real-world adversaries employ dynamic evasion techniques, polymorphic obfuscation, time-delayed staging, multi-stage downloads, and context-dependent activation that cannot be fully captured in static laboratory suites alone.
