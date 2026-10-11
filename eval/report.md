# PackageGuard Benchmark Evaluation Report

## 1. Summary Metrics (Threat Detection Class: Malicious, Typosquat, Tampered)
- **Total Evaluated Packages (Binary Matrix)**: 8
- **True Positives (TP)**: 3
- **False Positives (FP)**: 0
- **True Negatives (TN)**: 5
- **False Negatives (FN)**: 0
- **Precision**: 100.0%
- **Recall / Detection Rate**: 100.0%
- **F1 Score**: 1.000
- **False Positive Rate (FPR)**: 0.0%

## 2. Vulnerability Assessment (Reported Separately)
| Package | Version | Category | Verdict | Score | Verification | Expected Verdict |
|---|---|---|---|---|---|---|
| vulnerable-pkg | 1.0.0 | vulnerable | **Block** | 60 | PartiallyVerified | Review |

## 3. Per-Package Evaluation Matrix
| Package | Version | Category | Ground Truth | Verdict | Score | Verification | Classification |
|---|---|---|---|---|---|---|---|
| clean-pkg | 1.0.0 | benign | benign | **Safe** | 100 | PartiallyVerified | TN |
| benign-tool | 1.0.0 | benign | benign | **Safe** | 93 | PartiallyVerified | TN |
| benign-base64 | 1.0.0 | benign | benign | **Safe** | 96 | PartiallyVerified | TN |
| benign-native-postinstall | 1.0.0 | benign | benign | **Safe** | 89 | PartiallyVerified | TN |
| event-stream-lite | 1.0.0 | benign | benign | **Safe** | 95 | PartiallyVerified | TN |
| event-stream-lite | 1.0.1 | malicious | malicious | **Block** | 34 | PartiallyVerified | TP |
| vulnerable-pkg | 1.0.0 | vulnerable | malicious | **Block** | 60 | PartiallyVerified | N/A |
| lodahs | 1.0.0 | typosquat | malicious | **Review** | 65 | PartiallyVerified | TP |
| tampered-pkg | 1.0.0 | tampered | malicious | **Block** | 60 | Unverified | TP |

## 4. Limitations & Real-World Caveats
> [!IMPORTANT]
> **Evaluation Limitations Disclaimer**:
> This benchmark operates against synthetic, defanged test fixtures engineered to model real-world attack vectors (e.g., event-stream supply chain injection, typosquatting, metadata manipulation, hash tampering, and known CVEs).
> **Synthetic fixtures do not establish real-world detection accuracy** in production ecosystems. Real-world adversaries employ dynamic evasion techniques, polymorphic obfuscation, time-delayed staging, multi-stage downloads, and context-dependent activation that cannot be fully captured in static laboratory suites alone.
