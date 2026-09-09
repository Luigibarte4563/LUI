import { BaseScanner, ScanContext } from './BaseScanner';
import { Finding, createFinding } from '../models/Finding';
import { getAllFiles, relativePath, getSnippetAt } from '../utils/fileUtils';

export class AuthScanner extends BaseScanner {
  private findingCounter = 100;

  constructor() {
    super('Auth Scanner', 'auth', 'Analyzes authentication implementation');
  }

  async scan(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const files = getAllFiles(
      context.rootPath,
      ['.js', '.ts', '.jsx', '.tsx', '.py', '.php', '.java', '.cs', '.rb'],
      [...(context.config.exclude as string[] || []), 'node_modules', 'vendor', 'dist', 'build']
    );

    for (const filePath of files) {
      const content = this.getFileContent(context, filePath);
      if (!content) continue;
      const relPath = relativePath(filePath, context.rootPath);
      if (this.isSelfSource(relPath)) continue;
      const lines = content.split('\n');

      // Check for weak password hashing
      const md5Match = content.match(/(?:md5|md5Crypto)\s*\(|createHash\s*\(\s*['"]md5['"]\s*\)/i);
      if (md5Match && (content.includes('password') || content.includes('passwd') || content.includes('hash'))) {
        this.findingCounter++;
        const line = this.getLineNumber(content, md5Match[0]);
        findings.push(createFinding({
          id: `LUI-AUTH-${String(this.findingCounter).padStart(3, '0')}`,
          title: 'Weak password hashing (MD5)',
          severity: 'CRITICAL',
          confidence: 'HIGH',
          category: 'Authentication',
          type: 'potential',
          description: 'MD5 is being used for password hashing, which is cryptographically broken.',
          impact: 'MD5 hashes can be reversed quickly using rainbow tables or GPU-accelerated brute force.',
          affectedFiles: [{ file: relPath, line, snippet: getSnippetAt(content, line, 1) }],
          evidence: ['MD5 detected in password-related context'],
          recommendation: 'Use Argon2id, bcrypt, or scrypt for password hashing.',
          remediation: 'Replace md5() with bcrypt.hashSync() or argon2.hash().',
          cwe: 'CWE-328',
          status: 'open',
          scanner: 'AuthScanner',
          timestamp: Date.now(),
        }));
      }

      // Check for plaintext password storage/comparison
      const plaintextMatch = content.match(/(?:password|passwd|req\.body\.password|user\.password)\s*(?:===|==|!==)\s*[^=]/gi);
      if (plaintextMatch && !content.includes('hash') && !content.includes('bcrypt') && !content.includes('compare')) {
        this.findingCounter++;
        const line = this.getLineNumber(content, plaintextMatch[0]);
        findings.push(createFinding({
          id: `LUI-AUTH-${String(this.findingCounter).padStart(3, '0')}`,
          title: 'Potential plaintext password comparison',
          severity: 'HIGH',
          confidence: 'MEDIUM',
          category: 'Authentication',
          type: 'potential',
          description: 'A password comparison appears to use direct string comparison rather than a secure hash comparison.',
          impact: 'Plaintext password comparison is vulnerable to timing attacks and exposes passwords in memory.',
          affectedFiles: [{ file: relPath, line, snippet: getSnippetAt(content, line, 1) }],
          evidence: ['Direct password comparison detected'],
          recommendation: 'Use bcrypt.compare() or a constant-time comparison function.',
          cwe: 'CWE-916',
          status: 'open',
          scanner: 'AuthScanner',
          timestamp: Date.now(),
        }));
      }

      // Check for token in localStorage
      for (const lsMatch of content.matchAll(/token[^\r\n]{0,80}localStorage|localStorage[^\r\n]{0,80}token/ig)) {
        const lsLine = this.getLineNumber(content, lsMatch[0], lsMatch.index);
        const lsLineText = lines[lsLine - 1] || '';
        if (lsLine <= 0 || lsLineText.trim().startsWith('//') || lsLineText.trim().startsWith('*')) continue;
        this.findingCounter++;
        findings.push(createFinding({
          id: `LUI-AUTH-${String(this.findingCounter).padStart(3, '0')}`,
          title: 'Token stored in localStorage',
          severity: 'MEDIUM',
          confidence: 'MEDIUM',
          category: 'Authentication',
          type: 'potential',
          description: 'Authentication token is stored in localStorage, which is accessible to JavaScript.',
          impact: 'If an XSS vulnerability exists, an attacker could steal the authentication token.',
          affectedFiles: [{ file: relPath, line: lsLine, snippet: getSnippetAt(content, lsLine, 1) }],
          evidence: ['localStorage token storage detected'],
          recommendation: 'Use HttpOnly cookies for session tokens or a secure token storage mechanism.',
          cwe: 'CWE-922',
          status: 'open',
          scanner: 'AuthScanner',
          timestamp: Date.now(),
        }));
        break;
      }

      // Check for session without secure flags
      if (content.includes('session') && content.includes('cookie') && !content.includes('httpOnly') && !content.includes('HttpOnly') && !content.includes('secure') && !content.includes('Secure')) {
        this.findingCounter++;
        const line = this.getLineNumber(content, 'session');
        findings.push(createFinding({
          id: `LUI-AUTH-${String(this.findingCounter).padStart(3, '0')}`,
          title: 'Session cookie without security flags',
          severity: 'MEDIUM',
          confidence: 'MEDIUM',
          category: 'Authentication',
          type: 'potential',
          description: 'Session cookies may not have HttpOnly and Secure flags set.',
          impact: 'Session cookies without security flags are vulnerable to theft via XSS or network interception.',
          affectedFiles: [{ file: relPath, line, snippet: getSnippetAt(content, line, 1) }],
          evidence: ['Session cookie configuration without security flags'],
          recommendation: 'Set HttpOnly and Secure flags on session cookies.',
          cwe: 'CWE-614',
          status: 'open',
          scanner: 'AuthScanner',
          timestamp: Date.now(),
        }));
      }

      // Check for missing JWT expiration
      const jwtMatch = content.match(/jwt\s*\.\s*sign\s*\(/i);
      if (jwtMatch && !content.includes('expiresIn') && !content.includes('expires')) {
        this.findingCounter++;
        const line = this.getLineNumber(content, jwtMatch[0]);
        findings.push(createFinding({
          id: `LUI-AUTH-${String(this.findingCounter).padStart(3, '0')}`,
          title: 'JWT token without expiration',
          severity: 'HIGH',
          confidence: 'MEDIUM',
          category: 'Authentication',
          type: 'potential',
          description: 'JWT tokens are being created without an expiration time.',
          impact: 'Tokens without expiration remain valid indefinitely, increasing the risk if they are compromised.',
          affectedFiles: [{ file: relPath, line, snippet: getSnippetAt(content, line, 1) }],
          evidence: ['JWT sign without expiresIn'],
          recommendation: 'Always set an appropriate expiration time for JWT tokens.',
          cwe: 'CWE-613',
          status: 'open',
          scanner: 'AuthScanner',
          timestamp: Date.now(),
        }));
      }

      // Check for weak token generation
      const randomMatches = content.matchAll(/\bMath\.random\s*\(/g);
      for (const randomMatch of randomMatches) {
        const rLine = this.getLineNumber(content, randomMatch[0], randomMatch.index);
        const rContext = lines.slice(Math.max(0, rLine - 2), Math.min(lines.length, rLine + 2)).join('\n');
        if (!/token|secret|session|key/i.test(rContext)) continue;

        this.findingCounter++;
        findings.push(createFinding({
          id: `LUI-AUTH-${String(this.findingCounter).padStart(3, '0')}`,
          title: 'Weak token generation',
          severity: 'HIGH',
          confidence: 'MEDIUM',
          category: 'Authentication',
          type: 'potential',
          description: 'A non-cryptographic random number generator may be used for token generation.',
          impact: 'Predictable tokens could allow session hijacking or account takeover.',
          affectedFiles: [{ file: relPath, line: rLine, snippet: getSnippetAt(content, rLine, 1) }],
          evidence: ['Weak random number generation for tokens'],
          recommendation: 'Use crypto.randomBytes() for generating security tokens.',
          cwe: 'CWE-330',
          status: 'open',
          scanner: 'AuthScanner',
          timestamp: Date.now(),
        }));
      }
    }

    return findings;
  }
}
