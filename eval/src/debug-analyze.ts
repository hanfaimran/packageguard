import crypto from 'node:crypto';
import * as acorn from 'acorn';
import { generateAllFixtures } from './fixtures/generator.js';
import { extractTarballInMemory } from '../../packages/core/src/parsers/tarball-extractor.js';
import { StaticAnalyzer } from '../../packages/core/src/scanners/static-analyzer.js';

const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

const fixtures: any = generateAllFixtures(privPem);
const v2 = fixtures['event-stream-lite@1.0.1'];

const files = await extractTarballInMemory(v2.tarballBytes);
console.log('EXTRACTED FILES:', files.map((f) => `${f.path} (${f.size} bytes)`));

const post = files.find((f) => f.path.includes('postinstall'));
console.log('\nPOSTINSTALL CONTENT:\n', post?.content);

try {
  acorn.parse(post?.content ?? '', { ecmaVersion: 'latest', sourceType: 'module' });
  console.log('\nacorn module parse: OK');
} catch (e) {
  console.log('\nacorn module parse FAILED:', (e as Error).message);
}
try {
  acorn.parse(post?.content ?? '', { ecmaVersion: 'latest', sourceType: 'script' });
  console.log('acorn script parse: OK');
} catch (e) {
  console.log('acorn script parse FAILED:', (e as Error).message);
}

const analyzer = new StaticAnalyzer();
const ev = analyzer.analyzeFiles(files, {
  packageName: 'event-stream-lite',
  ecosystem: 'npm',
  version: '1.0.1',
  registryMetadata: v2.packageDocument,
} as any);
console.log('\nSTATIC ANALYZER EVIDENCE COUNT:', ev.length);
console.dir(ev.map((e) => ({ sev: e.severity, id: e.id, key: e.dedupKey, desc: e.description })), { depth: 3 });