import crypto from 'node:crypto';
import type { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, PutCommand, GetCommand } from '@aws-sdk/lib-dynamodb';
import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';
import { scanFromRegistry, type Report } from '@packageguard/core';
import { validatePackageInput, validateBodySize, jsonResponse } from './validation.js';

const ddbRawClient = new DynamoDBClient({});
export const ddbDocClient = DynamoDBDocumentClient.from(ddbRawClient);
export const s3Client = new S3Client({});

const SCANS_TABLE = process.env.SCANS_TABLE_NAME || 'packageguard-scans';
const REPORTS_BUCKET = process.env.REPORTS_BUCKET_NAME || 'packageguard-reports';

export interface ScanRequestBody {
  package: string;
  version: string;
  registryUrl?: string;
}

export async function postScanHandler(
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> {
  try {
    const sizeCheck = validateBodySize(event.body, 32768);
    if (!sizeCheck.valid) {
      return jsonResponse(400, { error: sizeCheck.error });
    }

    let parsed: ScanRequestBody;
    try {
      parsed = JSON.parse(event.body!);
    } catch {
      return jsonResponse(400, { error: 'Malformed JSON in request body' });
    }

    const inputCheck = validatePackageInput(parsed.package, parsed.version);
    if (!inputCheck.valid) {
      return jsonResponse(400, { error: inputCheck.error });
    }

    const packageName = parsed.package.trim();
    const version = parsed.version.trim();
    const scanId = crypto.randomUUID();
    const now = new Date().toISOString();

    // Run core engine scan
    let report: Report;
    try {
      report = await scanFromRegistry(packageName, version, {
        registryUrl: parsed.registryUrl || process.env.NPM_REGISTRY_URL,
      });
    } catch (err) {
      return jsonResponse(400, {
        error: `Failed to scan package: ${(err as Error).message}`,
      });
    }

    const s3Key = `reports/${packageName}/${version}/${scanId}.json`;

    // 1. Store full JSON report in KMS-encrypted S3 bucket
    await s3Client.send(
      new PutObjectCommand({
        Bucket: REPORTS_BUCKET,
        Key: s3Key,
        Body: JSON.stringify(report, null, 2),
        ContentType: 'application/json',
      }),
    );

    // 2. Store metadata record in DynamoDB
    await ddbDocClient.send(
      new PutCommand({
        TableName: SCANS_TABLE,
        Item: {
          id: scanId,
          package: packageName,
          version,
          riskScore: report.riskScore,
          verdict: report.verdict,
          verificationStatus: report.verificationStatus,
          hardBlocksCount: report.hardBlocks.length,
          evidenceCount: report.evidence.length,
          reportS3Key: s3Key,
          scannedAt: now,
          createdAt: Math.floor(Date.now() / 1000),
        },
      }),
    );

    return jsonResponse(201, {
      scanId,
      report,
    });
  } catch (err) {
    console.error('Unhandled error in postScanHandler:', err);
    return jsonResponse(500, { error: 'Internal server error processing scan' });
  }
}

export async function getScanByIdHandler(
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> {
  try {
    const scanId = event.pathParameters?.id;
    if (!scanId || typeof scanId !== 'string' || !/^[0-9a-fA-F-]{1,64}$/.test(scanId)) {
      return jsonResponse(400, { error: 'Invalid or missing scan ID path parameter' });
    }

    // Retrieve metadata from DynamoDB
    const ddbRes = await ddbDocClient.send(
      new GetCommand({
        TableName: SCANS_TABLE,
        Key: { id: scanId },
      }),
    );

    if (!ddbRes.Item) {
      return jsonResponse(404, { error: `Scan record with ID "${scanId}" not found` });
    }

    const item = ddbRes.Item;
    const s3Key = item.reportS3Key as string;

    // Fetch full report from S3
    try {
      const s3Res = await s3Client.send(
        new GetObjectCommand({
          Bucket: REPORTS_BUCKET,
          Key: s3Key,
        }),
      );

      const reportJson = await s3Res.Body?.transformToString();
      const report = reportJson ? JSON.parse(reportJson) : null;

      return jsonResponse(200, {
        scanId: item.id,
        package: item.package,
        version: item.version,
        riskScore: item.riskScore,
        verdict: item.verdict,
        verificationStatus: item.verificationStatus,
        scannedAt: item.scannedAt,
        report,
      });
    } catch (s3Err) {
      console.warn(`S3 report fetch failed for key ${s3Key}:`, s3Err);
      // Fallback: return DynamoDB summary record
      return jsonResponse(200, {
        scanId: item.id,
        package: item.package,
        version: item.version,
        riskScore: item.riskScore,
        verdict: item.verdict,
        verificationStatus: item.verificationStatus,
        scannedAt: item.scannedAt,
      });
    }
  } catch (err) {
    console.error('Unhandled error in getScanByIdHandler:', err);
    return jsonResponse(500, { error: 'Internal server error retrieving scan' });
  }
}
