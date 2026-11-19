import type { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import {
  parseGithubRepoUrl,
  fetchRepoLockfile,
  scanRepoDependencies,
  scanFromRegistry,
  type GithubRepoRef,
} from '@packageguard/core';
import { validateBodySize, jsonResponse } from './validation.js';

// API Gateway cuts requests off at 29 seconds, so the hosted version scans fewer packages.
export const HOSTED_MAX_DEPENDENCIES = 10;

export async function postScanRepoHandler(
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> {
  try {
    const sizeCheck = validateBodySize(event.body, 2048);
    if (!sizeCheck.valid) {
      return jsonResponse(400, { error: sizeCheck.error });
    }

    let parsed: { repoUrl?: unknown };
    try {
      parsed = JSON.parse(event.body!);
    } catch {
      return jsonResponse(400, { error: 'Malformed JSON in request body' });
    }

    if (typeof parsed.repoUrl !== 'string' || !parsed.repoUrl.trim()) {
      return jsonResponse(400, { error: 'Field "repoUrl" is required, e.g. https://github.com/owner/repo' });
    }

    let ref: GithubRepoRef;
    try {
      ref = parseGithubRepoUrl(parsed.repoUrl);
    } catch (err) {
      return jsonResponse(400, { error: (err as Error).message });
    }

    try {
      const lockfile = await fetchRepoLockfile(ref, { token: process.env.GITHUB_TOKEN });
      const result = await scanRepoDependencies(lockfile, {
        repoLabel: `${ref.owner}/${ref.repo}`,
        maxDependencies: HOSTED_MAX_DEPENDENCIES,
        scanDependency: (name, version) =>
          scanFromRegistry(name, version, { registryUrl: process.env.NPM_REGISTRY_URL }),
      });
      return jsonResponse(200, result);
    } catch (err) {
      return jsonResponse(400, { error: `Failed to scan repository: ${(err as Error).message}` });
    }
  } catch (err) {
    console.error('Unhandled error in postScanRepoHandler:', err);
    return jsonResponse(500, { error: 'Internal server error processing repository scan' });
  }
}