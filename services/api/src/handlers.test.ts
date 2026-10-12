import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { APIGatewayProxyEvent } from 'aws-lambda';
import { mockClient } from 'aws-sdk-client-mock';
import { DynamoDBDocumentClient, PutCommand, GetCommand, QueryCommand, ScanCommand } from '@aws-sdk/lib-dynamodb';
import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';
import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';

// Mock @packageguard/core scanFromRegistry before importing handlers
vi.mock('@packageguard/core', async () => {
  const actual = await vi.importActual<typeof import('@packageguard/core')>('@packageguard/core');
  return {
    ...actual,
    scanFromRegistry: vi.fn(),
  };
});

import { scanFromRegistry, type Report } from '@packageguard/core';
import { postScanHandler, getScanByIdHandler, ddbDocClient, s3Client } from './scan-handlers.js';
import {
  getHistoryHandler,
  nightlyRescanHandler,
  ddbDocClient as historyDdbDocClient,
  s3Client as historyS3Client,
  snsClient,
} from './history-and-scheduled-handlers.js';

const ddbMock = mockClient(DynamoDBDocumentClient);
const s3Mock = mockClient(S3Client);
const snsMock = mockClient(SNSClient);

const mockScanFromRegistry = vi.mocked(scanFromRegistry);

function createMockEvent(overrides: Partial<APIGatewayProxyEvent> = {}): APIGatewayProxyEvent {
  return {
    body: null,
    headers: {},
    multiValueHeaders: {},
    httpMethod: 'POST',
    isBase64Encoded: false,
    path: '/scan',
    pathParameters: null,
    queryStringParameters: null,
    multiValueQueryStringParameters: null,
    stageVariables: null,
    requestContext: {} as any,
    resource: '',
    ...overrides,
  };
}

describe('PackageGuard Lambda Handlers', () => {
  beforeEach(() => {
    ddbMock.reset();
    s3Mock.reset();
    snsMock.reset();
    vi.clearAllMocks();
    process.env.SCANS_TABLE_NAME = 'packageguard-scans';
    process.env.WATCHLIST_TABLE_NAME = 'packageguard-watchlist';
    process.env.REPORTS_BUCKET_NAME = 'packageguard-reports';
    process.env.ALERTS_TOPIC_ARN = 'arn:aws:sns:us-east-1:123456789012:packageguard-alerts';
  });

  // =========================================================================
  // 1. POST /scan Handler Tests
  // =========================================================================
  describe('postScanHandler', () => {
    it('successfully scans a package, saves report to S3 and DynamoDB, and returns 201 with report', async () => {
      const mockReport: Report = {
        package: 'lodash',
        version: '4.17.21',
        riskScore: 100,
        verdict: 'Safe',
        verificationStatus: 'Verified',
        breakdown: [],
        hardBlocks: [],
        evidence: [],
        remediation: [],
      };
      mockScanFromRegistry.mockResolvedValueOnce(mockReport);

      s3Mock.on(PutObjectCommand).resolves({});
      ddbMock.on(PutCommand).resolves({});

      const event = createMockEvent({
        body: JSON.stringify({ package: 'lodash', version: '4.17.21' }),
      });

      const result = await postScanHandler(event);
      expect(result.statusCode).toBe(201);

      const parsed = JSON.parse(result.body);
      expect(parsed.scanId).toBeDefined();
      expect(parsed.report).toEqual(mockReport);

      // Verify S3 put
      expect(s3Mock.calls()).toHaveLength(1);
      const s3Input = s3Mock.call(0).args[0].input;
      expect(s3Input.Bucket).toBe('packageguard-reports');
      expect(s3Input.Key).toContain('reports/lodash/4.17.21/');

      // Verify DynamoDB put
      expect(ddbMock.calls()).toHaveLength(1);
      const ddbInput = ddbMock.call(0).args[0].input as any;
      expect(ddbInput.TableName).toBe('packageguard-scans');
      expect(ddbInput.Item.package).toBe('lodash');
      expect(ddbInput.Item.verdict).toBe('Safe');
    });

    it('returns 400 when package name is invalid', async () => {
      const event = createMockEvent({
        body: JSON.stringify({ package: 'INVALID PACKAGE NAME!', version: '1.0.0' }),
      });

      const result = await postScanHandler(event);
      expect(result.statusCode).toBe(400);
      const parsed = JSON.parse(result.body);
      expect(parsed.error).toContain('Invalid package name format');
    });

    it('returns 400 when version format is invalid', async () => {
      const event = createMockEvent({
        body: JSON.stringify({ package: 'lodash', version: 'not-a-semver-version' }),
      });

      const result = await postScanHandler(event);
      expect(result.statusCode).toBe(400);
      const parsed = JSON.parse(result.body);
      expect(parsed.error).toContain('Invalid version format');
    });

    it('returns 400 when request body is oversized (> 32KB)', async () => {
      const hugePadding = 'x'.repeat(35000);
      const event = createMockEvent({
        body: JSON.stringify({ package: 'lodash', version: '1.0.0', pad: hugePadding }),
      });

      const result = await postScanHandler(event);
      expect(result.statusCode).toBe(400);
      const parsed = JSON.parse(result.body);
      expect(parsed.error).toContain('exceeds maximum allowed size');
    });

    it('returns 400 when body is empty', async () => {
      const event = createMockEvent({ body: null });
      const result = await postScanHandler(event);
      expect(result.statusCode).toBe(400);
      expect(JSON.parse(result.body).error).toContain('Request body must not be empty');
    });
  });

  // =========================================================================
  // 2. GET /scan/{id} Handler Tests
  // =========================================================================
  describe('getScanByIdHandler', () => {
    it('returns 200 with stored report when scan id exists', async () => {
      const scanId = '8b7e28b1-3829-4d69-9599-2a94fb001f3e';
      const mockReport: Report = {
        package: 'express',
        version: '4.18.2',
        riskScore: 95,
        verdict: 'Safe',
        verificationStatus: 'Verified',
        breakdown: [],
        hardBlocks: [],
        evidence: [],
        remediation: [],
      };

      ddbMock.on(GetCommand).resolves({
        Item: {
          id: scanId,
          package: 'express',
          version: '4.18.2',
          riskScore: 95,
          verdict: 'Safe',
          verificationStatus: 'Verified',
          reportS3Key: 'reports/express/4.18.2/test.json',
          scannedAt: '2026-10-12T00:00:00.000Z',
        },
      });

      s3Mock.on(GetObjectCommand).resolves({
        Body: {
          transformToString: async () => JSON.stringify(mockReport),
        } as any,
      });

      const event = createMockEvent({
        httpMethod: 'GET',
        path: `/scan/${scanId}`,
        pathParameters: { id: scanId },
      });

      const result = await getScanByIdHandler(event);
      expect(result.statusCode).toBe(200);
      const parsed = JSON.parse(result.body);
      expect(parsed.scanId).toBe(scanId);
      expect(parsed.report).toEqual(mockReport);
    });

    it('returns 404 when scan record does not exist in DynamoDB', async () => {
      ddbMock.on(GetCommand).resolves({ Item: undefined });

      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/scan/non-existent-id',
        pathParameters: { id: 'non-existent-id' },
      });

      const result = await getScanByIdHandler(event);
      expect(result.statusCode).toBe(404);
      expect(JSON.parse(result.body).error).toContain('not found');
    });

    it('returns 400 when scan id path parameter is missing', async () => {
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/scan/',
        pathParameters: null,
      });

      const result = await getScanByIdHandler(event);
      expect(result.statusCode).toBe(400);
      expect(JSON.parse(result.body).error).toContain('Invalid or missing scan ID');
    });
  });

  // =========================================================================
  // 3. GET /history Handler Tests
  // =========================================================================
  describe('getHistoryHandler', () => {
    it('returns 200 with list of past scans when package query param is provided', async () => {
      ddbMock.on(QueryCommand).resolves({
        Items: [
          {
            id: 'scan-1',
            package: 'lodash',
            version: '4.17.21',
            riskScore: 100,
            verdict: 'Safe',
            verificationStatus: 'Verified',
            hardBlocksCount: 0,
            evidenceCount: 0,
            scannedAt: '2026-10-12T02:00:00.000Z',
          },
          {
            id: 'scan-0',
            package: 'lodash',
            version: '4.17.20',
            riskScore: 90,
            verdict: 'Safe',
            verificationStatus: 'Verified',
            hardBlocksCount: 0,
            evidenceCount: 1,
            scannedAt: '2026-10-10T02:00:00.000Z',
          },
        ],
      });

      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/history',
        queryStringParameters: { package: 'lodash' },
      });

      const result = await getHistoryHandler(event);
      expect(result.statusCode).toBe(200);

      const parsed = JSON.parse(result.body);
      expect(parsed.package).toBe('lodash');
      expect(parsed.count).toBe(2);
      expect(parsed.scans).toHaveLength(2);
      expect(parsed.scans[0].scanId).toBe('scan-1');
    });

    it('returns 400 when package query parameter is omitted', async () => {
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/history',
        queryStringParameters: null,
      });

      const result = await getHistoryHandler(event);
      expect(result.statusCode).toBe(400);
      expect(JSON.parse(result.body).error).toContain('Query parameter "package" is required');
    });
  });

  // =========================================================================
  // 4. Nightly Re-scan Handler & SNS Alert Tests
  // =========================================================================
  describe('nightlyRescanHandler', () => {
    it('publishes an SNS alert when a previously Safe package degrades to Block or Review', async () => {
      // Watchlist item was previously 'Safe'
      ddbMock.on(ScanCommand).resolves({
        Items: [
          {
            package: 'event-stream-lite',
            version: '1.0.1',
            lastKnownVerdict: 'Safe',
            lastScannedAt: '2026-10-11T02:00:00.000Z',
          },
        ],
      });

      // New scan detects malware -> verdict: 'Block'
      const degradedReport: Report = {
        package: 'event-stream-lite',
        version: '1.0.1',
        riskScore: 0,
        verdict: 'Block',
        verificationStatus: 'Verified',
        breakdown: [],
        hardBlocks: ['Correlated credential exfiltration detected in package'],
        evidence: [],
        remediation: [],
      };
      mockScanFromRegistry.mockResolvedValueOnce(degradedReport);

      s3Mock.on(PutObjectCommand).resolves({});
      ddbMock.on(PutCommand).resolves({});
      snsMock.on(PublishCommand).resolves({ MessageId: 'msg-123' });

      const res = await nightlyRescanHandler();

      expect(res.rescannedCount).toBe(1);
      expect(res.alertedCount).toBe(1);
      expect(res.alerts[0].package).toBe('event-stream-lite');
      expect(res.alerts[0].previousVerdict).toBe('Safe');
      expect(res.alerts[0].newVerdict).toBe('Block');

      // Verify SNS publish was triggered
      expect(snsMock.calls()).toHaveLength(1);
      const snsInput = snsMock.call(0).args[0].input;
      expect(snsInput.TopicArn).toBe('arn:aws:sns:us-east-1:123456789012:packageguard-alerts');
      expect(snsInput.Subject).toContain('Security Degradation: event-stream-lite@1.0.1 is now Block');
      expect(snsInput.Message).toContain('SECURITY ALERT');
    });

    it('does NOT publish an SNS alert when a package verdict remains unchanged (e.g. Safe -> Safe)', async () => {
      ddbMock.on(ScanCommand).resolves({
        Items: [
          {
            package: 'clean-pkg',
            version: '1.0.0',
            lastKnownVerdict: 'Safe',
            lastScannedAt: '2026-10-11T02:00:00.000Z',
          },
        ],
      });

      const cleanReport: Report = {
        package: 'clean-pkg',
        version: '1.0.0',
        riskScore: 100,
        verdict: 'Safe',
        verificationStatus: 'Verified',
        breakdown: [],
        hardBlocks: [],
        evidence: [],
        remediation: [],
      };
      mockScanFromRegistry.mockResolvedValueOnce(cleanReport);

      s3Mock.on(PutObjectCommand).resolves({});
      ddbMock.on(PutCommand).resolves({});

      const res = await nightlyRescanHandler();

      expect(res.rescannedCount).toBe(1);
      expect(res.alertedCount).toBe(0);
      expect(res.alerts).toHaveLength(0);

      // Verify no SNS alert was published
      expect(snsMock.calls()).toHaveLength(0);
    });
  });
});
