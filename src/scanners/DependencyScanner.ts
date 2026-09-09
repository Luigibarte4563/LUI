import * as fs from 'fs';
import * as path from 'path';
import { BaseScanner, ScanContext } from './BaseScanner';
import { Finding, createFinding } from '../models/Finding';
import { fileExists, relativePath } from '../utils/fileUtils';
import { findVulnerabilities, isVersionAffected } from '../knowledge/vulnerabilityDatabase';

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

  constructor() {
    super('Dependency Scanner', 'dependencies', 'Analyzes dependencies for vulnerabilities and issues');
  }

  async scan(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Node.js dependencies
    const pkgJsonPath = path.join(context.rootPath, 'package.json');
    if (fileExists(pkgJsonPath)) {
      findings.push(...this.scanPackageJson(context, pkgJsonPath));
    }

    // PHP dependencies
    const composerPath = path.join(context.rootPath, 'composer.json');
    if (fileExists(composerPath)) {
      findings.push(...this.scanComposerJson(context, composerPath));
    }

    // Python dependencies
    const reqPath = path.join(context.rootPath, 'requirements.txt');
    if (fileExists(reqPath)) {
      findings.push(...this.scanRequirementsTxt(context, reqPath));
    }

    return findings;
  }

  private scanPackageJson(context: ScanContext, pkgPath: string): Finding[] {
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
        
        // Check known vulnerabilities
        for (const vuln of findVulnerabilities(name, ver)) {
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

  private scanComposerJson(context: ScanContext, composerPath: string): Finding[] {
    const findings: Finding[] = [];
    try {
      const content = fs.readFileSync(composerPath, 'utf-8');
      const composer = JSON.parse(content);
      const deps = composer.require || {};
      const relPath = relativePath(composerPath, context.rootPath);

      for (const [name, version] of Object.entries(deps)) {
        const ver = (version as string).replace(/^[\^~>=<]*/, '');
        for (const vuln of findVulnerabilities(name, ver)) {
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

  private scanRequirementsTxt(context: ScanContext, reqPath: string): Finding[] {
    const findings: Finding[] = [];
    try {
      const content = fs.readFileSync(reqPath, 'utf-8');
      const lines = content.split('\n').filter(l => l.trim() && !l.startsWith('#'));
      const relPath = relativePath(reqPath, context.rootPath);

      for (const line of lines) {
        const match = line.match(/^([a-zA-Z0-9_-]+)\s*[=><]+\s*([0-9.]+)/);
        if (match) {
          const [, name, ver] = match;
          for (const vuln of findVulnerabilities(name, ver)) {
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
