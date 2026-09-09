import { BaseScanner, ScanContext } from './BaseScanner';
import { Finding, createFinding } from '../models/Finding';
import { getAllFiles, relativePath, getSnippetAt } from '../utils/fileUtils';

interface SASTRule {
  id: string;
  name: string;
  pattern: RegExp;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  category: string;
  description: string;
  impact: string;
  recommendation: string;
  cwe: string;
  languages: string[];
}

const SAST_RULES: SASTRule[] = [
  // SQL Injection
  {
    id: 'SAST-001',
    name: 'SQL Injection',
    pattern: /(?:query|execute|raw|exec)\s*\(\s*(?:`[^`]*\$\{|['"][^'"]*\$\{|["][^"]*\$\{|\+\s*(?:req\.|params\.|body\.|query\.|request\.))/gi,
    severity: 'HIGH',
    confidence: 'MEDIUM',
    category: 'Injection',
    description: 'User-controlled input appears to be interpolated into a SQL query.',
    impact: 'An attacker could manipulate the database query to access, modify, or delete data.',
    recommendation: 'Use parameterized queries or prepared statements instead of string interpolation.',
    cwe: 'CWE-89',
    languages: ['JavaScript', 'TypeScript', 'Python', 'PHP', 'Ruby'],
  },
  {
    id: 'SAST-001b',
    name: 'SQL Injection',
    pattern: /(?:SELECT|INSERT|UPDATE|DELETE)\s+[^;]*\+\s*(?:req\.|params\.|body\.|query\.|input|userId|user_id|searchTerm)/gi,
    severity: 'HIGH',
    confidence: 'HIGH',
    category: 'Injection',
    description: 'SQL query is constructed using string concatenation with user input.',
    impact: 'An attacker could manipulate the database query to access, modify, or delete data.',
    recommendation: 'Use parameterized queries or prepared statements.',
    cwe: 'CWE-89',
    languages: ['JavaScript', 'TypeScript', 'PHP', 'Java'],
  },
  {
    id: 'SAST-002',
    name: 'SQL Injection (String Concatenation)',
    pattern: /(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|AND|OR)\s+['"]?\s*\+\s*(?:req\.|params\.|body\.|query\.|request\.|input)/gi,
    severity: 'HIGH',
    confidence: 'HIGH',
    category: 'Injection',
    description: 'SQL keywords are being concatenated with user input.',
    impact: 'An attacker could inject arbitrary SQL commands.',
    recommendation: 'Use parameterized queries or an ORM to prevent SQL injection.',
    cwe: 'CWE-89',
    languages: ['JavaScript', 'TypeScript', 'PHP', 'Java'],
  },
  {
    id: 'SAST-003',
    name: 'SQL Injection (Raw Query)',
    pattern: /(?:db|connection|pool)\.(?:query|execute|run|raw)\s*\(\s*['"][^'"]*\+(?!\s*['"])/gi,
    severity: 'HIGH',
    confidence: 'MEDIUM',
    category: 'Injection',
    description: 'A raw SQL query is being constructed with string concatenation.',
    impact: 'Potential SQL injection vulnerability.',
    recommendation: 'Use parameterized queries with placeholder values.',
    cwe: 'CWE-89',
    languages: ['JavaScript', 'TypeScript', 'PHP'],
  },

  // XSS
  {
    id: 'SAST-010',
    name: 'Dangerous innerHTML',
    pattern: /\.innerHTML\s*=\s*(?!['"][^'"]*['"])(?!`[^`]*`)/gi,
    severity: 'HIGH',
    confidence: 'MEDIUM',
    category: 'XSS',
    description: 'innerHTML is being set with potentially dynamic content.',
    impact: 'Could lead to Cross-Site Scripting (XSS) if user-controlled content is used.',
    recommendation: 'Use textContent for plain text or a sanitization library for HTML content.',
    cwe: 'CWE-79',
    languages: ['JavaScript', 'TypeScript'],
  },
  {
    id: 'SAST-010b',
    name: 'Reflected XSS',
    pattern: /res\.send\s*\(\s*['"][^'"]*<[^'"]*['"]\s*\+\s*(?:req\.|params\.|body\.|query\.|searchTerm)/gi,
    severity: 'HIGH',
    confidence: 'HIGH',
    category: 'XSS',
    description: 'User input is concatenated into HTML response without sanitization.',
    impact: 'An attacker could inject malicious scripts into the page.',
    recommendation: 'Sanitize user input before including it in HTML responses.',
    cwe: 'CWE-79',
    languages: ['JavaScript', 'TypeScript'],
  },
  {
    id: 'SAST-011',
    name: 'dangerouslySetInnerHTML',
    pattern: /dangerouslySetInnerHTML\s*=\s*\{\s*\{[^}]*\}\s*\}/gi,
    severity: 'MEDIUM',
    confidence: 'MEDIUM',
    category: 'XSS',
    description: 'React dangerouslySetInnerHTML is being used, which bypasses React\'s XSS protection.',
    impact: 'Could lead to XSS if the HTML content includes untrusted data.',
    recommendation: 'Sanitize HTML content using a library like DOMPurify before rendering.',
    cwe: 'CWE-79',
    languages: ['JavaScript', 'TypeScript'],
  },
  {
    id: 'SAST-012',
    name: 'eval() Usage',
    pattern: /(?:^|[^.\w])eval\s*\(/gm,
    severity: 'HIGH',
    confidence: 'LOW',
    category: 'Injection',
    description: 'eval() is used, which can execute arbitrary code.',
    impact: 'If user-controlled input reaches eval(), it could lead to Remote Code Execution.',
    recommendation: 'Avoid eval(). If dynamic evaluation is needed, use a safe alternative like JSON.parse().',
    cwe: 'CWE-95',
    languages: ['JavaScript', 'TypeScript', 'PHP'],
  },
  {
    id: 'SAST-013',
    name: 'new Function() Usage',
    pattern: /new\s+Function\s*\(/g,
    severity: 'HIGH',
    confidence: 'MEDIUM',
    category: 'Injection',
    description: 'new Function() creates a function from a string, similar to eval().',
    impact: 'Could lead to code injection if user input is involved.',
    recommendation: 'Avoid using new Function(). Use object lookups or switch statements instead.',
    cwe: 'CWE-95',
    languages: ['JavaScript', 'TypeScript'],
  },
  {
    id: 'SAST-014',
    name: 'setTimeout with String',
    pattern: /setTimeout\s*\(\s*['"`]/g,
    severity: 'MEDIUM',
    confidence: 'HIGH',
    category: 'Injection',
    description: 'setTimeout is being called with a string, which behaves like eval().',
    impact: 'Could lead to code injection if the string contains user-controlled content.',
    recommendation: 'Pass a function reference instead of a string to setTimeout.',
    cwe: 'CWE-95',
    languages: ['JavaScript', 'TypeScript'],
  },

  // Command Injection
  {
    id: 'SAST-020',
    name: 'Command Injection (child_process)',
    pattern: /(?:child_process\.)?(?:exec|execSync|spawn|spawnSync)\s*\(/g,
    severity: 'HIGH',
    confidence: 'MEDIUM',
    category: 'Command Injection',
    description: 'A child process execution function is being used.',
    impact: 'If user input reaches the command, it could lead to Remote Code Execution.',
    recommendation: 'Use execFile or spawn with an array of arguments. Never interpolate user input into commands.',
    cwe: 'CWE-78',
    languages: ['JavaScript', 'TypeScript'],
  },
  {
    id: 'SAST-021',
    name: 'Command Injection (Python)',
    pattern: /(?:os\.system|os\.popen|subprocess\.call|subprocess\.run|subprocess\.Popen)\s*\(/g,
    severity: 'HIGH',
    confidence: 'MEDIUM',
    category: 'Command Injection',
    description: 'A system command execution function is being used in Python.',
    impact: 'If user input reaches the command, it could lead to Remote Code Execution.',
    recommendation: 'Use subprocess with shell=False and pass arguments as a list.',
    cwe: 'CWE-78',
    languages: ['Python'],
  },
  {
    id: 'SAST-022',
    name: 'Command Injection (PHP)',
    pattern: /(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(/g,
    severity: 'HIGH',
    confidence: 'MEDIUM',
    category: 'Command Injection',
    description: 'A PHP command execution function is being used.',
    impact: 'If user input reaches the command, it could lead to Remote Code Execution.',
    recommendation: 'Use escapeshellarg() and escapeshellcmd() for user input. Consider using PHP\'s built-in functions instead.',
    cwe: 'CWE-78',
    languages: ['PHP'],
  },

  // Path Traversal
  {
    id: 'SAST-030',
    name: 'Path Traversal',
    pattern: /(?:readFile|readFileSync|createReadStream|readfile|open|fopen|require)\s*\(.*(?:req\.|params\.|body\.|query\.|input|\.\.\/|\.\.\\)/gi,
    severity: 'HIGH',
    confidence: 'MEDIUM',
    category: 'Path Traversal',
    description: 'File system operation with potentially user-controlled path.',
    impact: 'An attacker could access arbitrary files on the server.',
    recommendation: 'Validate and sanitize file paths. Use path.resolve() and verify the resolved path is within expected directories.',
    cwe: 'CWE-22',
    languages: ['JavaScript', 'TypeScript', 'PHP', 'Python'],
  },
  {
    id: 'SAST-030b',
    name: 'Path Traversal',
    pattern: /(?:readFileSync|readFile)\s*\(\s*(?:req\.|params\.|body\.|query\.|filePath|filename)/gi,
    severity: 'HIGH',
    confidence: 'HIGH',
    category: 'Path Traversal',
    description: 'File system read operation uses user-controlled input as the path.',
    impact: 'An attacker could read arbitrary files on the server.',
    recommendation: 'Validate file paths against a whitelist of allowed directories.',
    cwe: 'CWE-22',
    languages: ['JavaScript', 'TypeScript', 'PHP', 'Python'],
  },
  {
    id: 'SAST-031',
    name: 'Path Traversal Pattern',
    pattern: /(?:readFile|readFileSync|sendFile|download|fopen|CreateFile|path\.(?:join|resolve|normalize))\s*\([^)]{0,80}(?:\.\.\/|\.\.\\)|%2e%2e%2f|%2e%2e\/|%2e%2e%5c/gi,
    severity: 'MEDIUM',
    confidence: 'LOW',
    category: 'Path Traversal',
    description: 'Path traversal pattern detected in code.',
    impact: 'This pattern could be used to access files outside the intended directory.',
    recommendation: 'Sanitize file paths and validate that they don\'t escape the expected directory.',
    cwe: 'CWE-22',
    languages: ['JavaScript', 'TypeScript', 'PHP', 'Python', 'Java', 'Go'],
  },

  // Weak Cryptography
  {
    id: 'SAST-040',
    name: 'MD5 for Passwords',
    pattern: /(?:md5|MD5)\s*\.\s*(?:update|digest|create)\s*\(|createHash\s*\(\s*['"]md5['"]\s*\)/gi,
    severity: 'CRITICAL',
    confidence: 'HIGH',
    category: 'Cryptography',
    description: 'MD5 is being used, which is cryptographically broken for password storage.',
    impact: 'MD5 hashes can be reversed quickly using rainbow tables or brute force.',
    recommendation: 'Use Argon2id, bcrypt, or scrypt for password hashing.',
    cwe: 'CWE-328',
    languages: ['JavaScript', 'TypeScript', 'PHP', 'Python', 'Java'],
  },
  {
    id: 'SAST-041',
    name: 'SHA-1 for Passwords',
    pattern: /createHash\s*\(\s*['"]sha1['"]\s*\)/gi,
    severity: 'HIGH',
    confidence: 'MEDIUM',
    category: 'Cryptography',
    description: 'SHA-1 is being used, which is deprecated for security purposes.',
    impact: 'SHA-1 is vulnerable to collision attacks and should not be used for password storage.',
    recommendation: 'Use SHA-256, SHA-3, or dedicated password hashing algorithms like bcrypt.',
    cwe: 'CWE-328',
    languages: ['JavaScript', 'TypeScript', 'PHP', 'Python', 'Java'],
  },
  {
    id: 'SAST-042',
    name: 'Weak Random Number Generator',
    pattern: /Math\.random\s*\(|random\.random\s*\(|rand\(\)/g,
    severity: 'MEDIUM',
    confidence: 'LOW',
    category: 'Cryptography',
    description: 'A non-cryptographic random number generator is being used.',
    impact: 'Predictable random numbers could compromise security tokens or keys.',
    recommendation: 'Use crypto.randomBytes() or crypto.getRandomValues() for security-sensitive randomness.',
    cwe: 'CWE-338',
    languages: ['JavaScript', 'TypeScript', 'Python', 'PHP'],
  },
  {
    id: 'SAST-043',
    name: 'Hardcoded Encryption Key',
    pattern: /(?:encryption|decrypt|encrypt|cipher|aes|AES)\s*(?:key|KEY)\s*[=:]\s*['"][^'"]{8,}['"]/gi,
    severity: 'CRITICAL',
    confidence: 'HIGH',
    category: 'Cryptography',
    description: 'A hardcoded encryption key was detected in the source code.',
    impact: 'Anyone with access to the source code can decrypt protected data.',
    recommendation: 'Store encryption keys in a secure key management system, never in source code.',
    cwe: 'CWE-321',
    languages: ['JavaScript', 'TypeScript', 'PHP', 'Python', 'Java', 'Go', 'Ruby'],
  },

  // Information Disclosure
  {
    id: 'SAST-050',
    name: 'Sensitive Data in Logs',
    pattern: /(?:console\.log|console\.error|console\.warn|print|log\.|logger\.)\s*\([^)]*(?:password|secret|token|key|credential|auth)[^)]*\)/gi,
    severity: 'MEDIUM',
    confidence: 'MEDIUM',
    category: 'Information Disclosure',
    description: 'Sensitive data may be written to application logs.',
    impact: 'Sensitive information could be exposed to log aggregation systems or unauthorized personnel.',
    recommendation: 'Never log sensitive data. Use redaction or masking for sensitive values.',
    cwe: 'CWE-532',
    languages: ['JavaScript', 'TypeScript', 'Python', 'PHP', 'Java'],
  },
  {
    id: 'SAST-051',
    name: 'Stack Trace Exposure',
    pattern: /(?:\.stack|stackTrace|traceback|stack_trace)\s*\.(?:toString|print|format)\s*\(/gi,
    severity: 'LOW',
    confidence: 'MEDIUM',
    category: 'Information Disclosure',
    description: 'Stack traces may be exposed to users.',
    impact: 'Stack traces can reveal internal application structure and potential vulnerabilities.',
    recommendation: 'Handle errors gracefully and don\'t expose stack traces to users in production.',
    cwe: 'CWE-209',
    languages: ['JavaScript', 'TypeScript', 'Python', 'PHP', 'Java'],
  },

  // SSRF
  {
    id: 'SAST-060',
    name: 'Potential SSRF',
    pattern: /(?:fetch|axios|request|http\.get|https\.get|got|node-fetch)\s*\(\s*(?:req\.|params\.|body\.|query\.|input|\$\{)/gi,
    severity: 'HIGH',
    confidence: 'MEDIUM',
    category: 'SSRF',
    description: 'An HTTP request is being made with potentially user-controlled URL.',
    impact: 'An attacker could make the server send requests to internal resources.',
    recommendation: 'Validate and whitelist allowed URLs. Use a URL parser and check against allowed schemes and hosts.',
    cwe: 'CWE-918',
    languages: ['JavaScript', 'TypeScript', 'Python', 'PHP', 'Go'],
  },

  // JWT Issues
  {
    id: 'SAST-070',
    name: 'JWT with None Algorithm',
    pattern: /(?:jwt\.verify|jwt\.decode|jsonwebtoken\.verify)\s*\([^)]*['"](none|None|NONE)['"]/gi,
    severity: 'CRITICAL',
    confidence: 'HIGH',
    category: 'Authentication',
    description: 'JWT is configured to accept the "none" algorithm.',
    impact: 'Attackers can forge tokens without knowing the signing key.',
    recommendation: 'Always specify allowed algorithms explicitly. Never allow "none".',
    cwe: 'CWE-347',
    languages: ['JavaScript', 'TypeScript'],
  },
  {
    id: 'SAST-071',
    name: 'JWT Without Expiration Check',
    pattern: /(?:jwt\.verify|jwt\.decode)\s*\([^)]*\)(?![\s\S]*expiresIn)(?![\s\S]*maxAge)/gi,
    severity: 'MEDIUM',
    confidence: 'LOW',
    category: 'Authentication',
    description: 'JWT verification may not be checking token expiration.',
    impact: 'Expired tokens could still be accepted by the application.',
    recommendation: 'Always validate JWT expiration using the exp claim.',
    cwe: 'CWE-613',
    languages: ['JavaScript', 'TypeScript'],
  },

  // Debug Mode
  {
    id: 'SAST-080',
    name: 'Debug Mode Enabled',
    pattern: /(?:DEBUG|debug)\s*[=:]\s*(?:true|1|'true'|"true"|'1'|"1")/gi,
    severity: 'MEDIUM',
    confidence: 'MEDIUM',
    category: 'Configuration',
    description: 'Debug mode appears to be enabled.',
    impact: 'Debug mode can expose sensitive information and reduce security.',
    recommendation: 'Disable debug mode in production environments.',
    cwe: 'CWE-489',
    languages: ['JavaScript', 'TypeScript', 'Python', 'PHP', 'Java'],
  },
  {
    id: 'SAST-081',
    name: 'Verbose Error Messages',
    pattern: /(?:catch\s*\([^)]*\)\s*\{[^}]*)(?:res\.status\(500\)\.send\((?:err|error|e)\.)|(?:print\((?:err|error|e)\.)/gi,
    severity: 'LOW',
    confidence: 'MEDIUM',
    category: 'Information Disclosure',
    description: 'Raw error objects may be returned to clients.',
    impact: 'Error messages may reveal internal implementation details.',
    recommendation: 'Return generic error messages to clients. Log detailed errors server-side.',
    cwe: 'CWE-209',
    languages: ['JavaScript', 'TypeScript', 'Python', 'PHP'],
  },
];

export class SASTScanner extends BaseScanner {
  private findingCounter = 0;

  constructor() {
    super('SAST Scanner', 'sast', 'Static Application Security Testing');
  }

  async scan(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const sourceExtensions = ['.js', '.ts', '.jsx', '.tsx', '.py', '.php', '.java', '.cs', '.go', '.rb'];
    const files = getAllFiles(
      context.rootPath,
      sourceExtensions,
      [...(context.config.exclude as string[] || []), 'node_modules', 'vendor', 'dist', 'build', '.min.js', '.bundle.js']
    );

    for (const filePath of files) {
      const content = this.getFileContent(context, filePath);
      if (!content) continue;
      if (content.length > 500000) continue; // Skip very large files

      const relPath = relativePath(filePath, context.rootPath);
      if (this.isSelfSource(relPath)) continue;
      const fileLang = this.detectLanguage(filePath);

      for (const rule of SAST_RULES) {
        if (rule.languages.length > 0 && !rule.languages.includes(fileLang)) continue;

        const matches = content.matchAll(rule.pattern);
        for (const match of matches) {
          const lineNumber = this.getLineNumber(content, match[0]);
          if (lineNumber <= 0) continue;

          // Skip matches in comments or in rule/descriptor metadata (name/description/impact strings).
          // These are Lui's own scanner rule tables, not application code.
          const matchedLine = content.split('\n')[lineNumber - 1] || '';
          if (this.isMetadataOrCommentLine(matchedLine)) continue;

          // Check context for better confidence
          const context = this.getLineContext(content, lineNumber);
          const adjustedConfidence = this.adjustConfidence(rule, context);
          const snippet = getSnippetAt(content, lineNumber, 1);

          this.findingCounter++;
          findings.push(createFinding({
            id: `LUI-CODE-${String(this.findingCounter).padStart(3, '0')}`,
            title: rule.name,
            severity: rule.severity,
            confidence: adjustedConfidence,
            category: rule.category,
            type: this.getFindingType(rule, context),
            description: rule.description,
            impact: rule.impact,
            affectedFiles: [{ file: relPath, line: lineNumber, snippet }],
            evidence: [match[0].substring(0, 100)],
            recommendation: rule.recommendation,
            cwe: rule.cwe,
            status: 'open',
            scanner: 'SASTScanner',
            timestamp: Date.now(),
          }));
        }
      }
    }

    return findings;
  }

  private isMetadataOrCommentLine(line: string): boolean {
    const t = line.trim();
    if (t.startsWith('//') || t.startsWith('*') || t.startsWith('/*') || t.startsWith('#')) return true;
    return /^(id|name|pattern|severity|confidence|category|type|description|impact|recommendation|evidence|cwe|languages|title|scanner|affectedFiles|snippet):/.test(t);
  }

  private detectLanguage(filePath: string): string {
    if (filePath.endsWith('.ts') || filePath.endsWith('.tsx') || filePath.endsWith('.mts')) return 'TypeScript';
    if (filePath.endsWith('.js') || filePath.endsWith('.jsx') || filePath.endsWith('.mjs') || filePath.endsWith('.cjs')) return 'JavaScript';
    if (filePath.endsWith('.py')) return 'Python';
    if (filePath.endsWith('.php')) return 'PHP';
    if (filePath.endsWith('.java')) return 'Java';
    if (filePath.endsWith('.cs')) return 'C#';
    if (filePath.endsWith('.go')) return 'Go';
    if (filePath.endsWith('.rb')) return 'Ruby';
    return 'JavaScript';
  }

  private getLineContext(content: string, lineNumber: number): string {
    const lines = content.split('\n');
    const start = Math.max(0, lineNumber - 5);
    const end = Math.min(lines.length, lineNumber + 5);
    return lines.slice(start, end).join('\n').toLowerCase();
  }

  private adjustConfidence(rule: SASTRule, context: string): 'HIGH' | 'MEDIUM' | 'LOW' {
    let confidence = rule.confidence;

    // Increase confidence if user input is nearby
    if (context.includes('req.body') || context.includes('req.query') || context.includes('req.params') ||
        context.includes('request.form') || context.includes('request.args') || context.includes('$_get') ||
        context.includes('$_post') || context.includes('$_request')) {
      confidence = 'HIGH';
    }

    // Decrease confidence if sanitization is nearby
    if (context.includes('sanitize') || context.includes('escape') || context.includes('validate') ||
        context.includes('parseInt') || context.includes('parseFloat') || context.includes('encode')) {
      confidence = 'LOW';
    }

    return confidence;
  }

  private getFindingType(rule: SASTRule, context: string): 'confirmed' | 'potential' | 'heuristic' {
    if (context.includes('req.body') || context.includes('req.query') || context.includes('req.params')) {
      return 'potential';
    }
    if (rule.confidence === 'HIGH') return 'potential';
    return 'heuristic';
  }
}
