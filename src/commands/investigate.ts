import chalk from 'chalk';
import * as fs from 'fs';
import * as path from 'path';
import { Finding, Severity } from '../models/Finding';

export interface SecurityIndicator {
  type: 'failed_login' | 'auth_anomaly' | 'suspicious_activity' | 'credential_exposure' | 'suspicious_file' | 'unusual_config';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  detail: string;
  evidence: string[];
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
}

export function investigateProject(rootPath: string): SecurityIndicator[] {
  const indicators: SecurityIndicator[] = [];

  indicators.push(...checkCredentialExposure(rootPath));
  indicators.push(...checkSuspiciousFiles(rootPath));
  indicators.push(...checkUnusualConfig(rootPath));
  indicators.push(...checkDebugModeExposure(rootPath));
  indicators.push(...checkWeakCryptoPatterns(rootPath));

  return indicators;
}

function checkCredentialExposure(rootPath: string): SecurityIndicator[] {
  const indicators: SecurityIndicator[] = [];
  const envFiles = findFiles(rootPath, /\.env/i);

  for (const envFile of envFiles) {
    try {
      const content = fs.readFileSync(envFile, 'utf-8');
      const lines = content.split('\n');
      const exposedKeys: string[] = [];

      for (const line of lines) {
        if (line.match(/(?:password|secret|api_key|apikey|token|private_key)\s*=\s*\S+/i)) {
          const key = line.split('=')[0]?.trim();
          if (key) exposedKeys.push(key);
        }
      }

      if (exposedKeys.length > 0) {
        indicators.push({
          type: 'credential_exposure',
          severity: 'HIGH',
          title: `${exposedKeys.length} credential(s) found in ${path.relative(rootPath, envFile)}`,
          detail: 'Credentials in plain text files may be exposed in version control or deployment.',
          evidence: exposedKeys.map(k => `${k}=<redacted>`),
          confidence: 'HIGH',
        });
      }
    } catch { /* skip unreadable files */ }
  }

  return indicators;
}

function checkSuspiciousFiles(rootPath: string): SecurityIndicator[] {
  const indicators: SecurityIndicator[] = [];
  const suspiciousPatterns = [
    { pattern: /\.pem$/i, title: 'Private key file found', severity: 'CRITICAL' as const },
    { pattern: /\.p12$/i, title: 'Certificate bundle found', severity: 'HIGH' as const },
    { pattern: /\.key$/i, title: 'Key file found', severity: 'CRITICAL' as const },
    { pattern: /id_rsa/i, title: 'SSH private key found', severity: 'CRITICAL' as const },
    { pattern: /\.htpasswd$/i, title: 'Htpasswd file found', severity: 'HIGH' as const },
    { pattern: /dump\.sql$/i, title: 'Database dump found', severity: 'MEDIUM' as const },
  ];

  const files = getAllFilesRecursive(rootPath);
  for (const file of files) {
    for (const { pattern, title, severity } of suspiciousPatterns) {
      if (pattern.test(path.basename(file))) {
        indicators.push({
          type: 'suspicious_file',
          severity,
          title,
          detail: `Found ${path.relative(rootPath, file)} in the project.`,
          evidence: [path.relative(rootPath, file)],
          confidence: 'HIGH',
        });
      }
    }
  }

  return indicators;
}

function checkUnusualConfig(rootPath: string): SecurityIndicator[] {
  const indicators: SecurityIndicator[] = [];

  const dockerFiles = findFiles(rootPath, /docker-compose/i);
  for (const file of dockerFiles) {
    try {
      const content = fs.readFileSync(file, 'utf-8');
      if (content.includes('privileged: true')) {
        indicators.push({
          type: 'unusual_config',
          severity: 'HIGH',
          title: 'Docker privileged container detected',
          detail: 'Privileged containers have full host access.',
          evidence: [`${path.relative(rootPath, file)}: privileged: true`],
          confidence: 'HIGH',
        });
      }
      if (content.includes('docker.sock')) {
        indicators.push({
          type: 'unusual_config',
          severity: 'CRITICAL',
          title: 'Docker socket mounted in container',
          detail: 'Mounting docker.sock allows container escape.',
          evidence: [`${path.relative(rootPath, file)}: docker.sock mount`],
          confidence: 'HIGH',
        });
      }
    } catch { /* skip */ }
  }

  return indicators;
}

function checkDebugModeExposure(rootPath: string): SecurityIndicator[] {
  const indicators: SecurityIndicator[] = [];
  const configFiles = findFiles(rootPath, /\.(?:yml|yaml|json|js|ts|env)$/i);

  for (const file of configFiles) {
    try {
      const content = fs.readFileSync(file, 'utf-8');
      if (content.match(/debug\s*[:=]\s*(?:true|1|on)/i)) {
        indicators.push({
          type: 'unusual_config',
          severity: 'MEDIUM',
          title: 'Debug mode enabled in configuration',
          detail: 'Debug mode in production can expose sensitive information.',
          evidence: [`${path.relative(rootPath, file)}: debug enabled`],
          confidence: 'MEDIUM',
        });
      }
    } catch { /* skip */ }
  }

  return indicators;
}

function checkWeakCryptoPatterns(rootPath: string): SecurityIndicator[] {
  const indicators: SecurityIndicator[] = [];
  const sourceFiles = findFiles(rootPath, /\.(?:js|ts|py|java|php)$/i);

  for (const file of sourceFiles) {
    try {
      const content = fs.readFileSync(file, 'utf-8');
      if (content.includes('md5') && (content.includes('password') || content.includes('hash'))) {
        indicators.push({
          type: 'suspicious_activity',
          severity: 'HIGH',
          title: 'MD5 used for password hashing',
          detail: 'MD5 is cryptographically broken for password storage.',
          evidence: [`${path.relative(rootPath, file)}: MD5 in password context`],
          confidence: 'HIGH',
        });
      }
    } catch { /* skip */ }
  }

  return indicators;
}

function findFiles(rootPath: string, pattern: RegExp): string[] {
  const results: string[] = [];
  const entries = fs.readdirSync(rootPath, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'dist') continue;
    const fullPath = path.join(rootPath, entry.name);
    if (entry.isDirectory()) {
      results.push(...findFiles(fullPath, pattern));
    } else if (pattern.test(entry.name)) {
      results.push(fullPath);
    }
  }
  return results;
}

function getAllFilesRecursive(dir: string): string[] {
  return findFiles(dir, /\.\w+$/);
}

export function printInvestigateResults(indicators: SecurityIndicator[]): void {
  console.log('');
  console.log(chalk.bold('  SECURITY INDICATORS'));
  console.log(chalk.gray('  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
  console.log('');

  if (indicators.length === 0) {
    console.log(chalk.green('  No security indicators detected.'));
    console.log('');
    return;
  }

  const grouped = {
    CRITICAL: indicators.filter(i => i.severity === 'CRITICAL'),
    HIGH: indicators.filter(i => i.severity === 'HIGH'),
    MEDIUM: indicators.filter(i => i.severity === 'MEDIUM'),
    LOW: indicators.filter(i => i.severity === 'LOW'),
  };

  const SEVERITY_COLORS: Record<string, typeof chalk.red> = {
    CRITICAL: chalk.bgRed.white,
    HIGH: chalk.red,
    MEDIUM: chalk.yellow,
    LOW: chalk.blue,
  };

  for (const [severity, items] of Object.entries(grouped)) {
    if (items.length === 0) continue;
    for (const item of items) {
      const color = SEVERITY_COLORS[severity] || chalk.gray;
      console.log(`  ${color(severity.padEnd(8))} ${item.title}`);
      console.log(`  ${chalk.gray(item.detail)}`);
      for (const ev of item.evidence) {
        console.log(`    ${chalk.gray(ev)}`);
      }
      console.log('');
    }
  }

  console.log(chalk.yellow('  Potential security incident indicators detected.'));
  console.log(chalk.gray('  Lui cannot confirm compromise from these artifacts alone.'));
  console.log('');
}
