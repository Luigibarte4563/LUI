import * as http from 'http';
import * as https from 'https';
import { URL } from 'url';
import { KnownVulnerability } from '../knowledge/vulnerabilityDatabase';

const NVD_API_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const CACHE_DIR = '.lui-cache';
const CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours
const REQUEST_DELAY = 2000; // 2 seconds between requests (NVD rate limit)

interface NVDCache {
  [key: string]: {
    data: KnownVulnerability[];
    timestamp: number;
  };
}

export class NVDFetcher {
  private cache: NVDCache = {};
  private cacheFile: string;
  private lastRequestTime = 0;

  constructor(private projectRoot: string) {
    this.cacheFile = require('path').join(projectRoot, CACHE_DIR, 'nvd-cache.json');
    this.loadCache();
  }

  async fetchVulnerabilities(packageName: string, version: string): Promise<KnownVulnerability[]> {
    const cacheKey = `${packageName}@${version}`;
    const cached = this.cache[cacheKey];
    
    if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
      return cached.data;
    }

    try {
      await this.rateLimit();
      const vulns = await this.queryNVD(packageName, version);
      this.cache[cacheKey] = { data: vulns, timestamp: Date.now() };
      this.saveCache();
      return vulns;
    } catch {
      return [];
    }
  }

  async fetchLatestCVEs(packageName: string, limit: number = 10): Promise<KnownVulnerability[]> {
    try {
      await this.rateLimit();
      const url = `${NVD_API_BASE}?keywordSearch=${encodeURIComponent(packageName)}&resultsPerPage=${limit}`;
      const response = await this.httpGet(url);
      const data = JSON.parse(response);
      
      return (data.vulnerabilities || []).map((v: any) => {
        const cve = v.cve || {};
        const desc = cve.descriptions?.find((d: any) => d.lang === 'en');
        const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0] || {};
        const cvssData = metrics.cvssData || {};
        
        return {
          package: packageName,
          versions: this.extractVersions(cve),
          severity: this.mapSeverity(cvssData.baseSeverity || metrics.baseSeverity || 'MEDIUM'),
          title: desc?.value || 'Unknown vulnerability',
          cwe: this.extractCWE(cve),
          cvss: cvssData.baseScore || 0,
          cve: cve.id || '',
          fixedIn: undefined,
        };
      });
    } catch {
      return [];
    }
  }

  private async queryNVD(packageName: string, version: string): Promise<KnownVulnerability[]> {
    const url = `${NVD_API_BASE}?keywordSearch=${encodeURIComponent(packageName)}&keywordExactMatch&resultsPerPage=20`;
    const response = await this.httpGet(url);
    const data = JSON.parse(response);
    
    const vulns: KnownVulnerability[] = [];
    
    for (const v of data.vulnerabilities || []) {
      const cve = v.cve || {};
      const desc = cve.descriptions?.find((d: any) => d.lang === 'en');
      const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0] || {};
      const cvssData = metrics.cvssData || {};
      
      const vuln: KnownVulnerability = {
        package: packageName,
        versions: this.extractVersions(cve),
        severity: this.mapSeverity(cvssData.baseSeverity || metrics.baseSeverity || 'MEDIUM'),
        title: desc?.value || 'Unknown vulnerability',
        cwe: this.extractCWE(cve),
        cvss: cvssData.baseScore || 0,
        cve: cve.id || '',
        fixedIn: this.extractFixedVersion(cve),
      };
      
      if (this.isVersionAffectedByRanges(version, vuln.versions)) {
        vulns.push(vuln);
      }
    }
    
    return vulns;
  }

  private extractVersions(cve: any): string[] {
    const versions: string[] = [];
    for (const config of cve.configurations || []) {
      for (const node of config.nodes || []) {
        for (const match of node.cpeMatch || []) {
          if (match.versionStartIncluding) {
            const end = match.versionEndExcluding || match.versionEndIncluding;
            if (end) {
              versions.push(`>=${match.versionStartIncluding} <${end}`);
            }
          }
        }
      }
    }
    return versions.length > 0 ? versions : ['*'];
  }

  private extractCWE(cve: any): string {
    for (const weakness of cve.weaknesses || []) {
      for (const desc of weakness.description || []) {
        if (desc.value && desc.value.startsWith('CWE-')) {
          return desc.value;
        }
      }
    }
    return 'CWE-0';
  }

  private extractFixedVersion(cve: any): string | undefined {
    for (const version of cve.versions || []) {
      if (version.version) {
        return version.version;
      }
    }
    return undefined;
  }

  private mapSeverity(severity: string): 'CRITICAL' | 'HIGH' | 'MEDIUM' {
    const s = severity.toUpperCase();
    if (s === 'CRITICAL') return 'CRITICAL';
    if (s === 'HIGH') return 'HIGH';
    return 'MEDIUM';
  }

  private isVersionAffectedByRanges(version: string, ranges: string[]): boolean {
    if (ranges.includes('*')) return true;
    // Simple version comparison for NVD results
    for (const range of ranges) {
      const match = range.match(/>=?\s*([\d.]+)\s*<?\s*<?\s*([\d.]*)/);
      if (match) {
        const [, min, max] = match;
        if (this.compareVersions(version, min) >= 0 && (!max || this.compareVersions(version, max) < 0)) {
          return true;
        }
      }
    }
    return false;
  }

  private compareVersions(a: string, b: string): number {
    const pa = a.split('.').map(Number);
    const pb = b.split('.').map(Number);
    for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
      const na = pa[i] || 0;
      const nb = pb[i] || 0;
      if (na > nb) return 1;
      if (na < nb) return -1;
    }
    return 0;
  }

  private async rateLimit(): Promise<void> {
    const now = Date.now();
    const elapsed = now - this.lastRequestTime;
    if (elapsed < REQUEST_DELAY) {
      await new Promise(resolve => setTimeout(resolve, REQUEST_DELAY - elapsed));
    }
    this.lastRequestTime = Date.now();
  }

  private httpGet(url: string): Promise<string> {
    return new Promise((resolve, reject) => {
      let target: URL;
      try {
        target = new URL(url);
      } catch {
        reject(new Error(`Invalid URL: ${url}`));
        return;
      }

      const lib = target.protocol === 'https:' ? https : http;
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 15000);

      const request = lib.get(target, { signal: controller.signal }, (res) => {
        let data = '';
        res.setEncoding('utf8');
        res.on('data', (chunk: string) => { data += chunk; });
        res.on('end', () => {
          clearTimeout(timeout);
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
            resolve(data);
          } else {
            reject(new Error(`NVD API returned HTTP ${res.statusCode}`));
          }
        });
      });

      request.on('error', (err) => {
        clearTimeout(timeout);
        reject(err);
      });
    });
  }

  private loadCache(): void {
    try {
      const fs = require('fs');
      if (fs.existsSync(this.cacheFile)) {
        this.cache = JSON.parse(fs.readFileSync(this.cacheFile, 'utf-8'));
      }
    } catch {
      this.cache = {};
    }
  }

  private saveCache(): void {
    try {
      const fs = require('fs');
      const path = require('path');
      const dir = path.dirname(this.cacheFile);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      fs.writeFileSync(this.cacheFile, JSON.stringify(this.cache, null, 2));
    } catch {
      // Ignore cache save errors
    }
  }
}
