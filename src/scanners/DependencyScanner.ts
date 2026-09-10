import * as fs from 'fs';
import * as path from 'path';
import { BaseScanner, ScanContext } from './BaseScanner';
import { Finding, createFinding } from '../models/Finding';
import { fileExists, relativePath } from '../utils/fileUtils';
import { findVulnerabilities, isVersionAffected, KnownVulnerability } from '../knowledge/vulnerabilityDatabase';
import { NVDFetcher } from '../knowledge/NVDFetcher';

interface PackageInfo {
  name: string;
  version: string;
  requirements?: string;
}

const OUTDATED_THRESHOLDS: Record<string, number> = {
  major: 3,
  minor: 6,
  patch: 12,
};

export class DependencyScanner extends BaseScanner {
  private findingCounter = 0;
  private nvdFetcher: NVDFetcher | null = null;
  private nvdCache: Map<string, KnownVulnerability[]> = new Map();

  constructor() {
    super('Dependency Scanner', 'dependencies', 'Analyzes dependencies for vulnerabilities and issues');
  }

  async scan(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Real-time NVD CVE fetching (opt-in) - makes dependency scanning dynamic
    const dynamicCveEnabled = context.config.dynamic_cve === true;
    if (dynamicCveEnabled) {
      this.nvdFetcher = new NVDFetcher(context.rootPath);
    }

    // Node.js dependencies
    const pkgJsonPath = path.join(context.rootPath, 'package.json');
    if (fileExists(pkgJsonPath)) {
      findings.push(...await this.scanPackageJson(context, pkgJsonPath));
    }

    // PHP dependencies
    const composerPath = path.join(context.rootPath, 'composer.json');
    if (fileExists(composerPath)) {
      findings.push(...await this.scanComposerJson(context, composerPath));
    }

    // Python dependencies
    const reqPath = path.join(context.rootPath, 'requirements.txt');
    if (fileExists(reqPath)) {
      findings.push(...await this.scanRequirementsTxt(context, reqPath));
    }

    return findings;
  }

  private async findAllVulnerabilities(name: string, version: string): Promise<KnownVulnerability[]> {
    // First check local database
    const localVulns = findVulnerabilities(name, version);
    if (localVulns.length > 0) return localVulns;

    // Check NVD cache
    const cacheKey = `${name}@${version}`;
    if (this.nvdCache.has(cacheKey)) {
      return this.nvdCache.get(cacheKey)!;
    }

    // Fetch from NVD API (dynamic)
    if (this.nvdFetcher) {
      try {
        const nvdVulns = await this.nvdFetcher.fetchVulnerabilities(name, version);
        this.nvdCache.set(cacheKey, nvdVulns);
        return nvdVulns;
      } catch {
        // NVD fetch failed, return empty
      }
    }

    return [];
  }

  private async scanPackageJson(context: ScanContext, pkgPath: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    try {
      const content = fs.readFileSync(pkgPath, 'utf-8');
      const pkg = JSON.parse(content);
      const deps = pkg.dependencies || {};
      const devDeps = pkg.devDependencies || {};
      const allDeps = { ...deps, ...devDeps };
      const relPath = relativePath(pkgPath, context.rootPath);

      for (const [name, version] of Object.entries(allDeps)) {
        const ver = (version as string).replace(/^[\^~>=<]*/, '');
        
        // Check known vulnerabilities (local + NVD)
        const vulns = await this.findAllVulnerabilities(name, ver);
        for (const vuln of vulns) {
          if (isVersionAffected(ver, vuln.versions)) {
              this.findingCounter++;
              findings.push(createFinding({
                id: `LUI-DEP-${String(this.findingCounter).padStart(3, '0')}`,
                title: `Vulnerable dependency: ${name}@${ver}`,
                severity: vuln.severity,
                confidence: 'HIGH',
                category: 'Dependencies',
                type: 'confirmed',
                description: `Package ${name}@${ver} has a known security vulnerability: ${vuln.title}`,
                impact: `This vulnerability may allow attackers to exploit ${vuln.title.toLowerCase()} in your application.`,
                affectedFiles: [{ file: relPath }],
                evidence: [`Package: ${name}@${ver}`, `Vulnerability: ${vuln.title}`, `CVE: ${vuln.cve || 'N/A'}`],
                recommendation: `Upgrade ${name} to version ${vuln.fixedIn || 'latest'} or later.`,
                cwe: vuln.cwe,
                status: 'open',
                scanner: 'DependencyScanner',
                timestamp: Date.now(),
              }));
              break;
            }
        }

        // Check for wildcard versions
        if (version === '*' || version === 'latest') {
          this.findingCounter++;
          findings.push(createFinding({
            id: `LUI-DEP-${String(this.findingCounter).padStart(3, '0')}`,
            title: `Unpinned dependency: ${name}`,
            severity: 'MEDIUM',
            confidence: 'HIGH',
            category: 'Dependencies',
            type: 'confirmed',
            description: `Package ${name} is using an unpinned version (${version}), which could introduce unexpected breaking changes or vulnerabilities.`,
            impact: 'Unpinned dependencies may introduce vulnerabilities or breaking changes without warning.',
            affectedFiles: [{ file: relPath }],
            evidence: [`Package: ${name}@${version}`],
            recommendation: 'Pin dependencies to specific versions using exact version numbers or lock files.',
            status: 'open',
            scanner: 'DependencyScanner',
            timestamp: Date.now(),
          }));
        }
      }

      // Check for excessive dependencies
      const depCount = Object.keys(deps).length;
      if (depCount > 50) {
        this.findingCounter++;
        findings.push(createFinding({
          id: `LUI-DEP-${String(this.findingCounter).padStart(3, '0')}`,
          title: 'Excessive number of dependencies',
          severity: 'LOW',
          confidence: 'HIGH',
          category: 'Dependencies',
          type: 'heuristic',
          description: `The project has ${depCount} production dependencies, which increases the attack surface.`,
          impact: 'More dependencies mean more potential vulnerabilities and a larger supply chain attack surface.',
          affectedFiles: [{ file: relPath }],
          evidence: [`Production dependencies: ${depCount}`],
          recommendation: 'Review and remove unnecessary dependencies. Consider using lighter alternatives.',
          status: 'open',
          scanner: 'DependencyScanner',
          timestamp: Date.now(),
        }));
      }

      // Check for dev dependencies in production
      const devDepNames = Object.keys(devDeps);
      if (devDepNames.length > 0 && deps) {
        const suspiciousDevDeps = devDepNames.filter(d => 
          d.includes('webpack') || d.includes('typescript') || d.includes('eslint') || 
          d.includes('jest') || d.includes('mocha') || d.includes('chai')
        );
        if (suspiciousDevDeps.length > 0) {
          // This is informational - devDeps are fine
        }
      }
    } catch {
      // Ignore parse errors
    }
    return findings;
  }

  private async scanComposerJson(context: ScanContext, composerPath: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    try {
      const content = fs.readFileSync(composerPath, 'utf-8');
      const composer = JSON.parse(content);
      const deps = composer.require || {};
      const relPath = relativePath(composerPath, context.rootPath);

      for (const [name, version] of Object.entries(deps)) {
        const ver = (version as string).replace(/^[\^~>=<]*/, '');
        const vulns = await this.findAllVulnerabilities(name, ver);
        for (const vuln of vulns) {
          if (vuln.package === name && isVersionAffected(ver, vuln.versions)) {
            this.findingCounter++;
            findings.push(createFinding({
              id: `LUI-DEP-${String(this.findingCounter).padStart(3, '0')}`,
              title: `Vulnerable dependency: ${name}@${ver}`,
              severity: vuln.severity,
              confidence: 'HIGH',
              category: 'Dependencies',
              type: 'confirmed',
              description: `Package ${name}@${ver} has a known security vulnerability: ${vuln.title}`,
              impact: `This vulnerability may allow exploitation of ${vuln.title.toLowerCase()}.`,
              affectedFiles: [{ file: relPath }],
              evidence: [`Package: ${name}@${ver}`, `Vulnerability: ${vuln.title}`, `CVE: ${vuln.cve || 'N/A'}`],
              recommendation: `Upgrade ${name} to version ${vuln.fixedIn || 'latest'} or later.`,
              cwe: vuln.cwe,
              status: 'open',
              scanner: 'DependencyScanner',
              timestamp: Date.now(),
            }));
              break;
            }
          }
        }
    } catch { /* ignore */ }
    return findings;
  }

  private async scanRequirementsTxt(context: ScanContext, reqPath: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    try {
      const content = fs.readFileSync(reqPath, 'utf-8');
      const lines = content.split('\n').filter(l => l.trim() && !l.startsWith('#'));
      const relPath = relativePath(reqPath, context.rootPath);

      for (const line of lines) {
        const match = line.match(/^([a-zA-Z0-9_-]+)\s*[=><]+\s*([0-9.]+)/);
        if (match) {
          const [, name, ver] = match;
          const vulns = await this.findAllVulnerabilities(name, ver);
          for (const vuln of vulns) {
            if (vuln.package.toLowerCase() === name.toLowerCase() && isVersionAffected(ver, vuln.versions)) {
              this.findingCounter++;
              findings.push(createFinding({
                id: `LUI-DEP-${String(this.findingCounter).padStart(3, '0')}`,
                title: `Vulnerable dependency: ${name}@${ver}`,
                severity: vuln.severity,
                confidence: 'HIGH',
                category: 'Dependencies',
                type: 'confirmed',
                description: `Package ${name}@${ver} has a known security vulnerability: ${vuln.title}`,
                impact: `This vulnerability may allow exploitation of ${vuln.title.toLowerCase()}.`,
                affectedFiles: [{ file: relPath }],
                evidence: [`Package: ${name}@${ver}`, `Vulnerability: ${vuln.title}`, `CVE: ${vuln.cve || 'N/A'}`],
                recommendation: `Upgrade ${name} to version ${vuln.fixedIn || 'latest'} or later.`,
                cwe: vuln.cwe,
                status: 'open',
                scanner: 'DependencyScanner',
                timestamp: Date.now(),
              }));
              break;
            }
          }
        }
      }
    } catch { /* ignore */ }
    return findings;
  }
}
