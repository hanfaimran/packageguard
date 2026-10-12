/**
 * Input validation utilities for PackageGuard API
 */

// npm package names: optional scope @scope/pkg or pkg
// up to 214 chars, lowercase, numbers, hyphens, underscores, dots
const NPM_PACKAGE_REGEX = /^(?:@[a-z0-9_.-]+\/)?[a-z0-9_.-]+$/;

// Semver format (or common tags like 1.0.0, 1.0.0-beta.1, 1.0.0-rc.1)
const VERSION_REGEX = /^[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9_.-]+)?$/;

export interface ValidationResult {
  valid: boolean;
  error?: string;
}

export function validatePackageInput(pkg: unknown, version: unknown): ValidationResult {
  if (!pkg || typeof pkg !== 'string') {
    return { valid: false, error: 'Field "package" is required and must be a non-empty string' };
  }
  const trimmedPkg = pkg.trim();
  if (trimmedPkg.length > 214 || !NPM_PACKAGE_REGEX.test(trimmedPkg)) {
    return {
      valid: false,
      error: `Invalid package name format "${pkg}". Must be a valid npm package name (e.g. "lodash" or "@scope/pkg").`,
    };
  }

  if (!version || typeof version !== 'string') {
    return { valid: false, error: 'Field "version" is required and must be a non-empty string' };
  }
  const trimmedVersion = version.trim();
  if (!VERSION_REGEX.test(trimmedVersion)) {
    return {
      valid: false,
      error: `Invalid version format "${version}". Must follow semver convention (e.g. "1.0.0").`,
    };
  }

  return { valid: true };
}

export function validateBodySize(body: string | null | undefined, maxBytes = 32768): ValidationResult {
  if (!body) {
    return { valid: false, error: 'Request body must not be empty' };
  }
  const byteLength = Buffer.byteLength(body, 'utf8');
  if (byteLength > maxBytes) {
    return {
      valid: false,
      error: `Request body exceeds maximum allowed size of ${maxBytes} bytes (received ${byteLength} bytes)`,
    };
  }
  return { valid: true };
}

export function jsonResponse(statusCode: number, data: unknown): {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
} {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-Api-Key',
    },
    body: JSON.stringify(data),
  };
}
