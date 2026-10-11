import crypto from 'node:crypto';
import * as sigstore from 'sigstore';
import type { Scanner, ScanContext, Evidence, VerificationStatus } from '../types.js';

export interface IntegrityVerificationResult {
  status: VerificationStatus;
  computedSha512: string;
  expectedSha512?: string;
  hashMatch: boolean;
  signatureValid: boolean;
  provenanceVerified: boolean;
  evidence: Evidence[];
}

export class IntegrityScanner implements Scanner {
  readonly name = 'IntegrityScanner';

  constructor(
    private readonly trustedPublicKeys: Record<string, string> = {},
    private readonly sigstoreVerifier?: (bundle: any) => Promise<boolean>,
  ) {}

  async collect(ctx: ScanContext): Promise<Evidence[]> {
    const result = await this.verify(ctx);
    return result.evidence;
  }

  async verify(ctx: ScanContext): Promise<IntegrityVerificationResult> {
    const evidence: Evidence[] = [];

    if (!ctx.tarballBytes || ctx.tarballBytes.length === 0) {
      evidence.push({
        id: `integrity-missing-tarball-${ctx.packageName}`,
        scanner: this.name,
        category: 'integrity',
        severity: 'HIGH',
        confidence: 1.0,
        description: `Tarball bytes unavailable for package ${ctx.packageName}@${ctx.version}`,
        dedupKey: `integrity:missing-tarball:${ctx.packageName}`,
      });
      return {
        status: 'Unverified',
        computedSha512: '',
        hashMatch: false,
        signatureValid: false,
        provenanceVerified: false,
        evidence,
      };
    }

    // 1. Compute SHA-512 digest
    const hash = crypto.createHash('sha512').update(ctx.tarballBytes).digest('base64');
    const computedDigest = `sha512-${hash}`;

    const versionDoc = (ctx.registryMetadata?.versions as Record<string, any>)?.[ctx.version] ||
      (ctx.registryMetadata as any);
    const expectedDigest: string | undefined = versionDoc?.dist?.integrity;

    let hashMatch = false;

    if (!expectedDigest) {
      evidence.push({
        id: `integrity-no-expected-${ctx.packageName}`,
        scanner: this.name,
        category: 'integrity',
        severity: 'MEDIUM',
        confidence: 0.9,
        description: `Registry metadata does not declare a dist.integrity digest for ${ctx.packageName}@${ctx.version}`,
        dedupKey: `integrity:no-expected-digest:${ctx.packageName}`,
        rawData: { computedDigest },
      });
    } else if (computedDigest !== expectedDigest) {
      hashMatch = false;
      evidence.push({
        id: `integrity-mismatch-${ctx.packageName}`,
        scanner: this.name,
        category: 'integrity',
        severity: 'CRITICAL',
        confidence: 1.0,
        description: `Tarball SHA-512 integrity mismatch for ${ctx.packageName}@${ctx.version}! Expected: ${expectedDigest}, Actual: ${computedDigest}`,
        dedupKey: `integrity:mismatch:${ctx.packageName}`,
        rawData: {
          expected: expectedDigest,
          actual: computedDigest,
        },
      });
    } else {
      hashMatch = true;
    }

    // 2. Registry ECDSA Signature verification over `${name}@${version}:${integrity}`
    let signatureValid = false;
    let signatureTested = false;
    const signatures: Array<{ keyid: string; sig: string }> = versionDoc?.dist?.signatures || [];

    if (signatures.length > 0 && expectedDigest) {
      signatureTested = true;
      const messageToVerify = `${ctx.packageName}@${ctx.version}:${expectedDigest}`;

      for (const sigObj of signatures) {
        const pubKey = this.trustedPublicKeys[sigObj.keyid];
        if (pubKey) {
          try {
            const verifier = crypto.createVerify('SHA256');
            verifier.update(messageToVerify);
            const isValid = verifier.verify(pubKey, sigObj.sig, 'base64');
            if (isValid) {
              signatureValid = true;
              break;
            }
          } catch {
            signatureValid = false;
          }
        }
      }

      if (!signatureValid) {
        // If keys were provided but verification failed
        const hasKeyForId = signatures.some((s) => Boolean(this.trustedPublicKeys[s.keyid]));
        if (hasKeyForId) {
          evidence.push({
            id: `integrity-invalid-signature-${ctx.packageName}`,
            scanner: this.name,
            category: 'integrity',
            severity: 'CRITICAL',
            confidence: 1.0,
            description: `Registry ECDSA signature verification failed for ${ctx.packageName}@${ctx.version}`,
            dedupKey: `integrity:invalid-sig:${ctx.packageName}`,
            rawData: { signatures },
          });
        }
      }
    }

    // 3. Sigstore provenance verification (best effort)
    let provenanceVerified = false;
    const attestations = versionDoc?.dist?.attestations;
    if (attestations?.provenance) {
      try {
        if (this.sigstoreVerifier) {
          provenanceVerified = await this.sigstoreVerifier(attestations.provenance);
        } else {
          // Cryptographic verification via sigstore library where bundle is provided
          if (typeof attestations.provenance === 'object' && attestations.provenance.bundle) {
            await sigstore.verify(attestations.provenance.bundle, ctx.tarballBytes);
            provenanceVerified = true;
          }
        }
      } catch (err) {
        // Cryptographic check failed or unsupported format
        provenanceVerified = false;
      }
    }

    // Output a verification status:
    // Verified: hash + signature + provenance ok
    // PartiallyVerified: hash ok but signature or provenance unavailable
    // Unverified: hash mismatch or signature invalid (or missing tarball)
    let status: VerificationStatus;

    if (!hashMatch || (signatureTested && !signatureValid && signatures.some((s) => Boolean(this.trustedPublicKeys[s.keyid])))) {
      status = 'Unverified';
    } else if (hashMatch && signatureValid && provenanceVerified) {
      status = 'Verified';
    } else if (hashMatch) {
      status = 'PartiallyVerified';
    } else {
      status = 'Unverified';
    }

    return {
      status,
      computedSha512: computedDigest,
      expectedSha512: expectedDigest,
      hashMatch,
      signatureValid,
      provenanceVerified,
      evidence,
    };
  }
}
