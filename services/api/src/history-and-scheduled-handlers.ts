import crypto from 'node:crypto';
import type { APIGatewayProxyEvent, APIGatewayProxyResult, ScheduledEvent } from 'aws-lambda';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, QueryCommand, ScanCommand, PutCommand } from '@aws-sdk/lib-dynamodb';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';
import { scanFromRegistry, type Report } from '@packageguard/core';
import { jsonResponse } from './validation.js';

const ddbRawClient = new DynamoDBClient({});
export const ddbDocClient = DynamoDBDocumentClient.from(ddbRawClient);
export const s3Client = new S3Client({});
export const snsClient = new SNSClient({});

const SCANS_TABLE = process.env.SCANS_TABLE_NAME || 'packageguard-scans';
const WATCHLIST_TABLE = process.env.WATCHLIST_TABLE_NAME || 'packageguard-watchlist';
const REPORTS_BUCKET = process.env.REPORTS_BUCKET_NAME || 'packageguard-reports';
const ALERTS_TOPIC_ARN = process.env.ALERTS_TOPIC_ARN || '';

/**
 * GET /history?package=<name>
 * Returns past scan records for the specified package, ordered by scan date.
 */
export async function getHistoryHandler(
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> {
  try {
    const pkgName = event.queryStringParameters?.package;
    if (!pkgName || typeof pkgName !== 'string' || pkgName.trim().length === 0) {
      return jsonResponse(400, {
        error: 'Query parameter "package" is required (e.g. ?package=lodash)',
      });
    }

    const trimmedPkg = pkgName.trim();

    // Query GSI PackageIndex on Scans Table
    const queryRes = await ddbDocClient.send(
      new QueryCommand({
        TableName: SCANS_TABLE,
        IndexName: 'PackageIndex',
        KeyConditionExpression: '#pkg = :pkg',
        ExpressionAttributeNames: {
          '#pkg': 'package',
        },
        ExpressionAttributeValues: {
          ':pkg': trimmedPkg,
        },
        ScanIndexForward: false, // Descending by date
      }),
    );

    const items = queryRes.Items || [];

    return jsonResponse(200, {
      package: trimmedPkg,
      count: items.length,
      scans: items.map((item) => ({
        scanId: item.id,
        version: item.version,
        riskScore: item.riskScore,
        verdict: item.verdict,
        verificationStatus: item.verificationStatus,
        hardBlocksCount: item.hardBlocksCount,
        evidenceCount: item.evidenceCount,
        scannedAt: item.scannedAt,
      })),
    });
  } catch (err) {
    console.error('Unhandled error in getHistoryHandler:', err);
    return jsonResponse(500, { error: 'Internal server error retrieving history' });
  }
}

export interface WatchlistItem {
  package: string;
  version: string;
  lastKnownVerdict?: 'Safe' | 'Review' | 'Block';
  lastScannedAt?: string;
  addedAt?: string;
}

export interface NightlyRescanResult {
  rescannedCount: number;
  alertedCount: number;
  alerts: Array<{
    package: string;
    version: string;
    previousVerdict: string;
    newVerdict: string;
    riskScore: number;
  }>;
}

/**
 * Scheduled Nightly Re-scan Handler
 * Scans packages in the watchlist table.
 * If a previously Safe package becomes Review or Block, publishes an alert to SNS.
 */
export async function nightlyRescanHandler(
  _event?: ScheduledEvent,
): Promise<NightlyRescanResult> {
  const result: NightlyRescanResult = {
    rescannedCount: 0,
    alertedCount: 0,
    alerts: [],
  };

  try {
    // 1. Scan watchlist table for items
    const scanRes = await ddbDocClient.send(
      new ScanCommand({
        TableName: WATCHLIST_TABLE,
      }),
    );

    const items = (scanRes.Items || []) as WatchlistItem[];

    for (const item of items) {
      result.rescannedCount++;
      const { package: pkgName, version, lastKnownVerdict } = item;

      let report: Report;
      try {
        report = await scanFromRegistry(pkgName, version, {
          registryUrl: process.env.NPM_REGISTRY_URL,
        });
      } catch (scanErr) {
        console.error(`Failed nightly re-scan for ${pkgName}@${version}:`, scanErr);
        continue;
      }

      const scanId = crypto.randomUUID();
      const now = new Date().toISOString();
      const s3Key = `reports/${pkgName}/${version}/${scanId}.json`;

      // Save report in S3
      await s3Client.send(
        new PutObjectCommand({
          Bucket: REPORTS_BUCKET,
          Key: s3Key,
          Body: JSON.stringify(report, null, 2),
          ContentType: 'application/json',
        }),
      );

      // Save scan record in Scans table
      await ddbDocClient.send(
        new PutCommand({
          TableName: SCANS_TABLE,
          Item: {
            id: scanId,
            package: pkgName,
            version,
            riskScore: report.riskScore,
            verdict: report.verdict,
            verificationStatus: report.verificationStatus,
            hardBlocksCount: report.hardBlocks.length,
            evidenceCount: report.evidence.length,
            reportS3Key: s3Key,
            scannedAt: now,
            rescan: true,
          },
        }),
      );

      // Update Watchlist item with current verdict
      await ddbDocClient.send(
        new PutCommand({
          TableName: WATCHLIST_TABLE,
          Item: {
            ...item,
            lastKnownVerdict: report.verdict,
            lastScannedAt: now,
          },
        }),
      );

      // Alert condition: previously Safe, now degraded to Review or Block
      const wasSafe = lastKnownVerdict === 'Safe';
      const isDegraded = report.verdict === 'Review' || report.verdict === 'Block';

      if (wasSafe && isDegraded) {
        result.alertedCount++;
        result.alerts.push({
          package: pkgName,
          version,
          previousVerdict: lastKnownVerdict,
          newVerdict: report.verdict,
          riskScore: report.riskScore,
        });

        if (ALERTS_TOPIC_ARN) {
          const alertMessage = {
            alarm: 'PackageSecurityDegradation',
            timestamp: now,
            package: pkgName,
            version,
            previousVerdict: lastKnownVerdict,
            newVerdict: report.verdict,
            riskScore: report.riskScore,
            hardBlocks: report.hardBlocks,
            evidenceCount: report.evidence.length,
            message: `SECURITY ALERT: Package ${pkgName}@${version} previously verified as Safe has degraded to ${report.verdict}!`,
          };

          await snsClient.send(
            new PublishCommand({
              TopicArn: ALERTS_TOPIC_ARN,
              Subject: `[PackageGuard Alert] Security Degradation: ${pkgName}@${version} is now ${report.verdict}`,
              Message: JSON.stringify(alertMessage, null, 2),
            }),
          );
        }
      }
    }
  } catch (err) {
    console.error('Fatal error in nightlyRescanHandler:', err);
    throw err;
  }

  return result;
}
