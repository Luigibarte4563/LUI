import { BaseScanner, ScanContext } from './BaseScanner';
import { Finding, createFinding } from '../models/Finding';
import { getAllFiles, relativePath, readFileSafe, fileExists } from '../utils/fileUtils';
import * as path from 'path';
import * as fs from 'fs';

export class ConfigScanner extends BaseScanner {
  private findingCounter = 400;

  constructor() {
    super('Config Scanner', 'configuration', 'Analyzes security configuration');
  }

  async scan(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Check .env files for sensitive values
    findings.push(...this.scanEnvFiles(context));

    // Check .gitignore
    findings.push(...this.scanGitignore(context));

    // Check for debug mode in config
    findings.push(...this.scanDebugMode(context));

    // Check for insecure CORS in config files
    findings.push(...this.scanCORSConfig(context));

    return findings;
  }

  private scanEnvFiles(context: ScanContext): Finding[] {
    const findings: Finding[] = [];
    try {
      const entries = fs.readdirSync(context.rootPath);
      for (const entry of entries) {
        if (entry.startsWith('.env') && !entry.endsWith('.example')) {
          const filePath = path.join(context.rootPath, entry);
          const content = readFileSafe(filePath);
          if (!content) continue;
          const relPath = relativePath(filePath, context.rootPath);
          const lines = content.split('\n');

          for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();
            if (!line || line.startsWith('#')) continue;

            const match = line.match(/^([A-Z_]+)\s*=\s*(.+)$/);
            if (match) {
              const [, key, value] = match;
              if (value && value.length > 0 && !value.startsWith('${')) {
                const sensitiveKeys = ['PASSWORD', 'SECRET', 'TOKEN', 'KEY', 'CREDENTIAL', 'API_KEY', 'PRIVATE_KEY', 'DB_PASSWORD', 'MYSQL_PASSWORD', 'POSTGRES_PASSWORD', 'REDIS_PASSWORD'];
                if (sensitiveKeys.some(sk => key.includes(sk))) {
                  this.findingCounter++;
                  findings.push(createFinding({
                    id: `LUI-CFG-${String(this.findingCounter).padStart(3, '0')}`,
                    title: `Sensitive value in ${entry}`,
                    severity: 'HIGH',
                    confidence: 'HIGH',
                    category: 'Configuration',
                    type: 'confirmed',
                    description: `A sensitive value (${key}) is stored in the ${entry} file.`,
                    impact: 'If this file is committed to version control, the secret could be exposed.',
                    affectedFiles: [{ file: relPath, line: i + 1 }],
                    evidence: [`Key: ${key}`],
                    recommendation: `Remove ${key} from ${entry} and store it in a secure secret management system. Add ${entry} to .gitignore.`,
                    cwe: 'CWE-312',
                    status: 'open',
                    scanner: 'ConfigScanner',
                    timestamp: Date.now(),
                  }));
                }
              }
            }
          }
        }
      }
    } catch { /* ignore */ }
    return findings;
  }

  private scanGitignore(context: ScanContext): Finding[] {
    const findings: Finding[] = [];
    const gitignorePath = path.join(context.rootPath, '.gitignore');
    
    if (!fileExists(gitignorePath)) {
      if (fileExists(path.join(context.rootPath, '.git'))) {
        this.findingCounter++;
        findings.push(createFinding({
          id: `LUI-CFG-${String(this.findingCounter).padStart(3, '0')}`,
          title: 'Missing .gitignore file',
          severity: 'LOW',
          confidence: 'HIGH',
          category: 'Configuration',
          type: 'confirmed',
          description: 'The project uses Git but does not have a .gitignore file.',
          impact: 'Sensitive files and build artifacts may be accidentally committed to version control.',
          affectedFiles: [{ file: '.gitignore' }],
          evidence: ['No .gitignore found in Git repository'],
          recommendation: 'Create a .gitignore file with appropriate exclusions for sensitive files and build artifacts.',
          status: 'open',
          scanner: 'ConfigScanner',
          timestamp: Date.now(),
        }));
      }
      return findings;
    }

    const content = readFileSafe(gitignorePath);
    if (!content) return findings;

    const importantPatterns = ['.env', 'credentials', '*.pem', '*.key', '*.p12', '*.pfx', '.htpasswd'];
    const missingPatterns = importantPatterns.filter(p => !content.includes(p));

    if (missingPatterns.length > 0) {
      this.findingCounter++;
      findings.push(createFinding({
        id: `LUI-CFG-${String(this.findingCounter).padStart(3, '0')}`,
        title: '.gitignore missing sensitive file patterns',
        severity: 'MEDIUM',
        confidence: 'HIGH',
        category: 'Configuration',
        type: 'confirmed',
        description: `The .gitignore file is missing patterns for sensitive files: ${missingPatterns.join(', ')}`,
        impact: 'Sensitive files matching these patterns could be accidentally committed to version control.',
        affectedFiles: [{ file: '.gitignore' }],
        evidence: [`Missing patterns: ${missingPatterns.join(', ')}`],
        recommendation: 'Add the missing patterns to .gitignore.',
        cwe: 'CWE-538',
        status: 'open',
        scanner: 'ConfigScanner',
        timestamp: Date.now(),
      }));
    }

    return findings;
  }

  private scanDebugMode(context: ScanContext): Finding[] {
    const findings: Finding[] = [];
    const files = getAllFiles(
      context.rootPath,
      ['.js', '.ts', '.json', '.yml', '.yaml', '.env', '.env.*'],
      [...(context.config.exclude as string[] || []), 'node_modules', 'vendor', 'dist', 'build']
    );

    for (const filePath of files) {
      const content = this.getFileContent(context, filePath);
      if (!content) continue;

      if (content.match(/(?:DEBUG|NODE_ENV)\s*[=:]\s*(?:true|'true'|"true"|development)/gi) &&
          !filePath.includes('.env.example') && !filePath.includes('test')) {
        this.findingCounter++;
        const relPath = relativePath(filePath, context.rootPath);
        const line = this.getLineNumber(content, 'DEBUG') || this.getLineNumber(content, 'NODE_ENV');
        findings.push(createFinding({
          id: `LUI-CFG-${String(this.findingCounter).padStart(3, '0')}`,
          title: 'Debug mode may be enabled',
          severity: 'MEDIUM',
          confidence: 'MEDIUM',
          category: 'Configuration',
          type: 'potential',
          description: 'Debug mode appears to be enabled in configuration.',
          impact: 'Debug mode can expose sensitive information and reduce security.',
          affectedFiles: [{ file: relPath, line }],
          evidence: ['Debug/development mode detected in configuration'],
          recommendation: 'Disable debug mode in production. Use environment variables to control debug settings.',
          cwe: 'CWE-489',
          status: 'open',
          scanner: 'ConfigScanner',
          timestamp: Date.now(),
        }));
      }
    }

    return findings;
  }

  private scanCORSConfig(context: ScanContext): Finding[] {
    const findings: Finding[] = [];
    const configFiles = getAllFiles(
      context.rootPath,
      ['.js', '.ts', '.json', '.yml', '.yaml'],
      [...(context.config.exclude as string[] || []), 'node_modules', 'vendor']
    );

    for (const filePath of configFiles) {
      const content = this.getFileContent(context, filePath);
      if (!content) continue;
      const relPath = relativePath(filePath, context.rootPath);
      if (this.isSelfSource(relPath)) continue;

      if (content.includes('origin: true') || content.includes("origin: '*'") || content.includes('origin: "*"') || content.includes('origin: "*"')) {
        this.findingCounter++;
        const line = this.getLineNumber(content, 'origin');
        findings.push(createFinding({
          id: `LUI-CFG-${String(this.findingCounter).padStart(3, '0')}`,
          title: 'Permissive CORS configuration',
          severity: 'MEDIUM',
          confidence: 'MEDIUM',
          category: 'Configuration',
          type: 'potential',
          description: 'CORS is configured to accept all origins.',
          impact: 'Overly permissive CORS can expose API data to unauthorized websites.',
          affectedFiles: [{ file: relPath, line }],
          evidence: ['CORS origin set to true or wildcard'],
          recommendation: 'Restrict CORS to specific trusted origins.',
          cwe: 'CWE-942',
          status: 'open',
          scanner: 'ConfigScanner',
          timestamp: Date.now(),
        }));
      }
    }

    return findings;
  }
}
