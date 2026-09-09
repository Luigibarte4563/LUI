import { BaseScanner, ScanContext } from './BaseScanner';
import { Finding, createFinding } from '../models/Finding';
import { maskSecret, getAllFiles, relativePath } from '../utils/fileUtils';

const SECRET_PATTERNS: Array<{
  pattern: RegExp;
  name: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  category: string;
  cwe: string;
}> = [
  { pattern: /(?:AKIA|ASIA)[A-Z0-9]{16}/g, name: 'AWS Access Key', severity: 'CRITICAL', category: 'Cloud Credentials', cwe: 'CWE-798' },
  { pattern: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi, name: 'AWS Secret Key', severity: 'CRITICAL', category: 'Cloud Credentials', cwe: 'CWE-798' },
  { pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g, name: 'Private Key', severity: 'CRITICAL', category: 'Cryptographic Keys', cwe: 'CWE-321' },
  { pattern: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/g, name: 'GitHub Token', severity: 'CRITICAL', category: 'Access Tokens', cwe: 'CWE-798' },
  { pattern: /(?:sk_live|pk_live)_[A-Za-z0-9]{24,}/g, name: 'Stripe API Key', severity: 'CRITICAL', category: 'API Keys', cwe: 'CWE-798' },
  { pattern: /(?:sk_test|pk_test)_[A-Za-z0-9]{24,}/g, name: 'Stripe Test Key', severity: 'MEDIUM', category: 'API Keys', cwe: 'CWE-798' },
  { pattern: /xox[bpas]-[A-Za-z0-9-]+/g, name: 'Slack Token', severity: 'CRITICAL', category: 'Access Tokens', cwe: 'CWE-798' },
  { pattern: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g, name: 'SendGrid API Key', severity: 'CRITICAL', category: 'API Keys', cwe: 'CWE-798' },
  { pattern: /AIza[0-9A-Za-z_-]{35}/g, name: 'Google API Key', severity: 'HIGH', category: 'API Keys', cwe: 'CWE-798' },
  { pattern: /ya29\.[0-9A-Za-z_-]+/g, name: 'Google OAuth Token', severity: 'HIGH', category: 'Access Tokens', cwe: 'CWE-798' },
  { pattern: /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/g, name: 'IP Address', severity: 'MEDIUM', category: 'Network Exposure', cwe: 'CWE-200' },
  { pattern: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}/g, name: 'JWT Token', severity: 'HIGH', category: 'Access Tokens', cwe: 'CWE-798' },
  { pattern: /(?:password|passwd|pwd)\s*[=:]\s*['"]([^'"]{8,})['"]/gi, name: 'Hardcoded Password', severity: 'HIGH', category: 'Credentials', cwe: 'CWE-798' },
  { pattern: /(?:secret|SECRET)\s*[=:]\s*['"]([^'"]{8,})['"]/gi, name: 'Hardcoded Secret', severity: 'HIGH', category: 'Credentials', cwe: 'CWE-798' },
  { pattern: /(?:api_key|apikey|API_KEY)\s*[=:]\s*['"]([^'"]{16,})['"]/gi, name: 'API Key', severity: 'HIGH', category: 'API Keys', cwe: 'CWE-798' },
  { pattern: /(?:token|TOKEN)\s*[=:]\s*['"]([^'"]{20,})['"]/gi, name: 'Access Token', severity: 'HIGH', category: 'Access Tokens', cwe: 'CWE-798' },
  { pattern: /(?:DATABASE_URL|DB_URL|MYSQL_URL|POSTGRES_URL|MONGO_URL)\s*[=:]\s*['"]([^'"]+)['"]/gi, name: 'Database Connection String', severity: 'CRITICAL', category: 'Database Credentials', cwe: 'CWE-798' },
  { pattern: /(?:SMTP_PASSWORD|EMAIL_PASSWORD|MAIL_PASSWORD)\s*[=:]\s*['"]([^'"]+)['"]/gi, name: 'SMTP Password', severity: 'HIGH', category: 'Email Credentials', cwe: 'CWE-798' },
  { pattern: /(?:encryption_key|ENCRYPTION_KEY|secret_key|SECRET_KEY)\s*[=:]\s*['"]([^'"]{16,})['"]/gi, name: 'Encryption Key', severity: 'CRITICAL', category: 'Cryptographic Keys', cwe: 'CWE-798' },
  { pattern: /(?:CLIENT_SECRET|client_secret)\s*[=:]\s*['"]([^'"]{16,})['"]/gi, name: 'OAuth Client Secret', severity: 'CRITICAL', category: 'OAuth Credentials', cwe: 'CWE-798' },
];

const SKIP_PATTERNS = [
  'node_modules', 'vendor', '.git', 'dist', 'build', 'coverage',
  '.min.js', '.bundle.js', '.map', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
  'composer.lock', 'go.sum', 'Cargo.lock',
];

export class SecretScanner extends BaseScanner {
  private findingCounter = 0;

  constructor() {
    super('Secret Scanner', 'secrets', 'Detects exposed secrets, API keys, and credentials');
  }

  supported(context: ScanContext): boolean {
    return true;
  }

  async scan(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const files = getAllFiles(
      context.rootPath,
      ['.js', '.ts', '.jsx', '.tsx', '.py', '.php', '.java', '.cs', '.go', '.rb', '.rs', '.json', '.yml', '.yaml', '.env', '.env.*', '.toml', '.ini', '.cfg', '.conf', '.xml', '.properties', '.env.local', '.env.production', '.env.development', '.env.staging'],
      [...context.config.exclude as string[] || []]
    );

    const envFiles = this.findEnvFiles(context.rootPath);
    const allFiles = [...new Set([...files, ...envFiles])];

    for (const filePath of allFiles) {
      if (SKIP_PATTERNS.some(skip => filePath.includes(skip))) continue;
      
      const content = this.getFileContent(context, filePath);
      if (!content) continue;

      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        // Skip comments
        if (line.trimStart().startsWith('//') || line.trimStart().startsWith('#') || line.trimStart().startsWith('*')) continue;

        for (const secretPattern of SECRET_PATTERNS) {
          const matches = line.matchAll(secretPattern.pattern);
          for (const match of matches) {
            const matched = match[0];
            // Skip obvious false positives
            if (this.isFalsePositive(matched, line, filePath)) continue;
            // Skip IP addresses in comments or common internal patterns
            if (secretPattern.name === 'IP Address' && this.isCommonIP(matched)) continue;
            
            this.findingCounter++;
            const relPath = relativePath(filePath, context.rootPath);
            findings.push(createFinding({
              id: `LUI-SEC-${String(this.findingCounter).padStart(3, '0')}`,
              title: `Potential secret: ${secretPattern.name}`,
              severity: secretPattern.severity,
              confidence: this.getConfidence(secretPattern.name, line),
              category: 'Secrets',
              type: 'potential',
              description: `A potential ${secretPattern.name} was detected in the source code.`,
              impact: 'Exposed credentials could allow unauthorized access to services, databases, or infrastructure.',
              affectedFiles: [{ file: relPath, line: i + 1, snippet: this.maskLine(line.trim()) }],
              evidence: [this.maskLine(matched)],
              recommendation: 'Remove the secret from source control, rotate the credential, and store it in a secure secret management system or environment variable.',
              remediation: '1. Remove the secret from the file.\n2. Rotate the credential immediately.\n3. Store secrets in environment variables or a secret manager.\n4. Add the file to .gitignore if it contains secrets.\n5. Check git history if the secret was previously committed.',
              references: ['https://cwe.mitre.org/data/definitions/798.html', 'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password'],
              cwe: secretPattern.cwe,
              status: 'open',
              scanner: 'SecretScanner',
              timestamp: Date.now(),
            }));
          }
        }
      }
    }

    return findings;
  }

  private findEnvFiles(rootPath: string): string[] {
    const envFiles: string[] = [];
    try {
      const entries = require('fs').readdirSync(rootPath);
      for (const entry of entries) {
        if (entry.startsWith('.env')) {
          envFiles.push(require('path').join(rootPath, entry));
        }
      }
    } catch { /* ignore */ }
    return envFiles;
  }

  private isFalsePositive(matched: string, line: string, filePath: string): boolean {
    // Skip test files (only specific test file patterns)
    const basename = require('path').basename(filePath);
    if (basename.includes('.test.') || basename.includes('.spec.') || basename.includes('__tests__')) return true;
    // Skip placeholder values
    if (matched.includes('xxx') || matched.includes('XXX') || matched.includes('your-') || matched.includes('CHANGE_ME') || matched.includes('placeholder')) return true;
    // Skip obvious documentation
    if (line.includes('// example') || line.includes('# example') || line.includes('TODO') || line.includes('FIXME')) return true;
    // Skip obviously short or non-random strings
    if (matched.length < 8) return true;
    return false;
  }

  private isCommonIP(ip: string): boolean {
    const common = ['0.0.0.0', '127.0.0.1', '255.255.255.255', '1.1.1.1', '8.8.8.8', '10.0.0.1', '192.168.1.1'];
    return common.includes(ip);
  }

  private maskLine(line: string): string {
    return line.replace(/(['"])([^'"]{8,})(['"])/g, (match, q1, secret, q2) => {
      return q1 + maskSecret(secret) + q2;
    });
  }

  private getConfidence(name: string, line: string): 'HIGH' | 'MEDIUM' | 'LOW' {
    const highConfidence = ['AWS Access Key', 'AWS Secret Key', 'Private Key', 'GitHub Token', 'Stripe API Key', 'Slack Token', 'SendGrid API Key'];
    if (highConfidence.includes(name)) return 'HIGH';
    if (line.includes('process.env') || line.includes('os.environ') || line.includes('getenv')) return 'MEDIUM';
    return 'MEDIUM';
  }
}
