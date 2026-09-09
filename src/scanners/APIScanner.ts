import { BaseScanner, ScanContext } from './BaseScanner';
import { Finding, createFinding } from '../models/Finding';
import { getAllFiles, relativePath, getSnippetAt } from '../utils/fileUtils';

export class APIScanner extends BaseScanner {
  private findingCounter = 300;

  constructor() {
    super('API Scanner', 'api', 'Analyzes API security configuration');
  }

  async scan(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const files = getAllFiles(
      context.rootPath,
      ['.js', '.ts', '.jsx', '.tsx', '.py', '.php'],
      [...(context.config.exclude as string[] || []), 'node_modules', 'vendor', 'dist', 'build']
    );

    for (const filePath of files) {
      const content = this.getFileContent(context, filePath);
      if (!content) continue;
      const relPath = relativePath(filePath, context.rootPath);
      if (this.isSelfSource(relPath)) continue;
      const lines = content.split('\n');

      // Check for CORS wildcard with credentials
      if (content.match(/Access-Control-Allow-Origin['"]?\s*[:=]\s*['"]?\*/i) && 
          (content.match(/Access-Control-Allow-Credentials['"]?\s*[:=]\s*['"]?true/i) || content.includes('credentials: true'))) {
        this.findingCounter++;
        const line = this.getLineNumber(content, 'Access-Control-Allow-Origin');
        findings.push(createFinding({
          id: `LUI-API-${String(this.findingCounter).padStart(3, '0')}`,
          title: 'CORS wildcard with credentials',
          severity: 'HIGH',
          confidence: 'HIGH',
          category: 'API Security',
          type: 'confirmed',
          description: 'CORS is configured to allow any origin while also allowing credentials.',
          impact: 'This allows any website to make authenticated requests to the API, potentially exposing sensitive data.',
          affectedFiles: [{ file: relPath, line, snippet: getSnippetAt(content, line, 2) }],
          evidence: ['Access-Control-Allow-Origin: * with credentials'],
          recommendation: 'Use a specific list of allowed origins instead of wildcard. Never combine wildcard origin with credentials.',
          cwe: 'CWE-942',
          status: 'open',
          scanner: 'APIScanner',
          timestamp: Date.now(),
        }));
      }

// Check for wildcard CORS (line-scoped so Lui does not flag its own source)
      for (let i = 0; i < lines.length; i++) {
        const t = lines[i];
        const isWildcard = t.includes("origin: '*'") || t.includes('origin: "*"') ||
                           t.includes('origin: true') || /origin\s*[:=]\s*true/i.test(t) ||
                           /(?:use|cors)\s*\(\s*['"]\*['"]/i.test(t);
        const hasCorsContext = /cors|CORS|Access-Control|Allow-Origin/i.test(t);
        if (isWildcard && hasCorsContext && !t.trim().startsWith('//') && !t.trim().startsWith('*') && !t.includes('content.match')) {
          this.findingCounter++;
          const line = i + 1;
          findings.push(createFinding({
            id: `LUI-API-${String(this.findingCounter).padStart(3, '0')}`,
            title: 'Permissive CORS configuration',
            severity: 'MEDIUM',
            confidence: 'MEDIUM',
            category: 'API Security',
            type: 'potential',
            description: 'CORS is configured to allow all origins.',
            impact: 'Overly permissive CORS can expose API data to unauthorized websites.',
            affectedFiles: [{ file: relPath, line, snippet: getSnippetAt(content, line, 2) }],
            evidence: ['Wildcard or permissive CORS origin'],
            recommendation: 'Restrict CORS to specific trusted origins.',
            cwe: 'CWE-942',
            status: 'open',
            scanner: 'APIScanner',
            timestamp: Date.now(),
          }));
          break;
        }
      }

      // Check for missing rate limiting
      const globalLimiter = content.match(/app\.use\(\s*limiter\s*\)/i);
      const apiLimiter = content.match(/app\.use\(\s*['"]\/([^'"]*)['"]\s*,\s*limiter\s*\)/i);
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.match(/(?:app|router)\.(post|put|delete)\s*\(\s*['"]\/(?:api\/)?(?:login|register|auth|signin|signup|password)/i)) {
          const context = lines.slice(Math.max(0, i - 2), Math.min(lines.length, i + 20)).join('\n');
          const routePathMatch = line.match(/(?:app|router)\.(?:post|put|delete)\s*\(\s*['"](\/[^'"]*)/i);
          const routePath = routePathMatch ? routePathMatch[1] : '';
          const covered = context.includes('rate') && context.includes('limit') ||
                          context.includes('limiter') || context.includes('rateLimit') ||
                          (globalLimiter !== null) ||
                          (apiLimiter !== null && routePath.startsWith('/' + apiLimiter[1]));
          if (!covered) {
            this.findingCounter++;
            findings.push(createFinding({
              id: `LUI-API-${String(this.findingCounter).padStart(3, '0')}`,
              title: 'Authentication endpoint without rate limiting',
              severity: 'MEDIUM',
              confidence: 'MEDIUM',
              category: 'API Security',
              type: 'potential',
              description: 'An authentication endpoint appears to lack rate limiting.',
              impact: 'Without rate limiting, attackers could attempt brute-force password attacks.',
              affectedFiles: [{ file: relPath, line: i + 1, snippet: getSnippetAt(content, i + 1, 2) }],
              evidence: ['Auth endpoint without rate limiting'],
              recommendation: 'Implement rate limiting on authentication endpoints.',
              cwe: 'CWE-770',
              status: 'open',
              scanner: 'APIScanner',
              timestamp: Date.now(),
            }));
          }
        }
      }

      // Check for exposed error details in API responses
      if (content.includes('res.status(500)') || content.includes('response.status(500)')) {
        const matches = content.matchAll(/(?:res|response)\.status\(500\)\.(?:json|send)\s*\(\s*\{?[^}]*\b(?:err|error)\b[^}]*\}/gi);
        for (const match of matches) {
          // Skip generic error messages (these are actually safe)
          if (/internal server/i.test(match[0]) || /something went wrong/i.test(match[0]) ||
              /generic/i.test(match[0]) || /server error/i.test(match[0])) continue;
          this.findingCounter++;
          const line = this.getLineNumber(content, match[0]);
          findings.push(createFinding({
            id: `LUI-API-${String(this.findingCounter).padStart(3, '0')}`,
            title: 'Verbose error response',
            severity: 'LOW',
            confidence: 'MEDIUM',
            category: 'API Security',
            type: 'potential',
            description: 'The API returns detailed error information in 500 responses.',
            impact: 'Verbose errors can reveal internal implementation details to attackers.',
            affectedFiles: [{ file: relPath, line, snippet: getSnippetAt(content, line, 2) }],
            evidence: ['Detailed error in 500 response'],
            recommendation: 'Return generic error messages. Log detailed errors server-side.',
            cwe: 'CWE-209',
            status: 'open',
            scanner: 'APIScanner',
            timestamp: Date.now(),
          }));
        }
      }

      // Check for missing input validation on API routes
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.match(/(?:app|router)\.(post|put|patch)\s*\(\s*['"]/i)) {
          const context = lines.slice(i, Math.min(lines.length, i + 15)).join('\n');
          if (!context.includes('validate') && !context.includes('schema') && !context.includes('joi') && 
              !context.includes('zod') && !context.includes('yup') && !context.includes('ajv') &&
              !context.includes('body(') && !context.includes('check(')) {
            this.findingCounter++;
            findings.push(createFinding({
              id: `LUI-API-${String(this.findingCounter).padStart(3, '0')}`,
              title: 'API endpoint without input validation',
              severity: 'LOW',
              confidence: 'LOW',
              category: 'API Security',
              type: 'heuristic',
              description: 'An API endpoint appears to lack explicit input validation.',
              impact: 'Without input validation, the endpoint may accept malformed or malicious data.',
              affectedFiles: [{ file: relPath, line: i + 1 }],
              evidence: ['No validation library or schema detected'],
              recommendation: 'Implement input validation using a schema validation library.',
              cwe: 'CWE-20',
              status: 'open',
              scanner: 'APIScanner',
              timestamp: Date.now(),
            }));
          }
        }
      }
    }

    return findings;
  }
}
