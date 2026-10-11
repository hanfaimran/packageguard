export interface RegistryPackageVersion {
  name: string;
  version: string;
  description?: string;
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  repository?: string | { type?: string; url?: string };
  dist?: {
    tarball?: string;
    shasum?: string;
    integrity?: string;
    signatures?: Array<{ keyid: string; sig: string }>;
    attestations?: {
      url?: string;
      provenance?: { predicateType?: string };
    };
  };
  _npmUser?: { name: string; email?: string };
  maintainers?: Array<{ name: string; email?: string }>;
}

export interface RegistryPackageDocument {
  name: string;
  'dist-tags'?: Record<string, string>;
  versions: Record<string, RegistryPackageVersion>;
  time?: Record<string, string>;
  maintainers?: Array<{ name: string; email?: string }>;
  repository?: string | { type?: string; url?: string };
}

export class RegistryClient {
  constructor(private readonly baseUrl: string = 'https://registry.npmjs.org') {}

  async getPackageDocument(name: string): Promise<RegistryPackageDocument> {
    const encodedName = name.startsWith('@')
      ? `@${encodeURIComponent(name.slice(1))}`
      : encodeURIComponent(name);
    const url = `${this.baseUrl.replace(/\/$/, '')}/${encodedName}`;
    const res = await fetch(url);
    if (!res.ok) {
      throw new Error(`Failed to fetch package metadata from registry: ${res.status} ${res.statusText}`);
    }
    return (await res.json()) as RegistryPackageDocument;
  }

  async downloadTarball(tarballUrl: string): Promise<Buffer> {
    const res = await fetch(tarballUrl);
    if (!res.ok) {
      throw new Error(`Failed to download tarball: ${res.status} ${res.statusText}`);
    }
    const arrayBuffer = await res.arrayBuffer();
    return Buffer.from(arrayBuffer);
  }
}
