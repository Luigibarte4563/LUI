import { BaseScanner, ScanContext } from './BaseScanner';
import { Finding, createFinding } from '../models/Finding';
import * as path from 'path';

export interface EndpointInfo {
  method: string;
  path: string;
  file: string;
  line: number;
  hasAuth: boolean;
  hasAuthz: boolean;
  hasValidation: boolean;
  isPublic: boolean;
}

const ROUTE_PATTERNS = [
  /(?:app|router|server)\.(?:get|post|put|delete|patch|options|head)\s*\(\s*['"`]([^'"`]+)/gi,
  /@(?:Get|Post|Put|Delete|Patch|Options|Head)\s*\(\s*['"`]([^'"`]+)/gi,
  /(?:Route|RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping)\s*\(\s*['"`]([^'"`]+)/gi,
  /path\s*\(\s*['"`]([^'"`]+)/gi,
  /(?:@app\.route|@blueprint\.route)\s*\(\s*['"`]([^'"`]+)/gi,
];

const AUTH_MIDDLEWARE = [
  /(?:authenticate|auth|requireAuth|isAuthenticated|verifyToken|requireLogin|protect|guard)/i,
  /(?:passport\.authenticate|jwt\.verify|bcrypt|session)/i,
  /(?:middleware\.auth|authMiddleware|authCheck)/i,
];

const AUTHZ_MIDDLEWARE = [
  /(?:authorize|isAdmin|checkRole|requireRole|hasPermission|canAccess)/i,
  /(?:roleCheck|permissionCheck|accessControl|acl)/i,
];

const VALIDATION_PATTERNS = [
  /(?:validate|sanitize|check|schema|joi|yup|zod|express-validator)/i,
  /(?:req\.check|req\.validationErrors|body\(|param\(|query\()/i,
];

const PUBLIC_PATHS = [
  /^\/(?:login|register|signup|signin|auth|oauth|callback|health|status|api\/products|api\/public)/i,
  /^\/forgot-password|^\/reset-password|^\/verify-email/i,
];

export class APIDiscoveryScanner extends BaseScanner {
  private findingCounter = 700;

  constructor() {
    super('API Discovery Scanner', 'api-discovery', 'Discovers and catalogs API endpoints');
  }

  async scan(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const endpoints: EndpointInfo[] = [];

    for (const file of context.project.sourceFiles) {
      const content = this.getFileContent(context, file);
      if (!content) continue;

      const ext = path.extname(file).toLowerCase();
      if (!['.js', '.ts', '.py', '.java', '.php', '.go', '.rb'].includes(ext)) continue;

      const lines = content.split('\n');
      const fileEndpoints = this.extractEndpoints(lines, file);

      for (const endpoint of fileEndpoints) {
        endpoints.push(endpoint);

        if (!endpoint.hasAuth && !endpoint.isPublic) {
          this.findingCounter++;
          findings.push(createFinding({
            id: `LUI-API-${String(this.findingCounter).padStart(3, '0')}`,
            title: `Endpoint without authentication: ${endpoint.method} ${endpoint.path}`,
            severity: 'MEDIUM',
            confidence: 'MEDIUM',
            category: 'API Security',
            type: 'potential',
            description: `The ${endpoint.method} ${endpoint.path} endpoint does not appear to have authentication middleware.`,
            impact: 'Unauthenticated access to potentially sensitive endpoints.',
            affectedFiles: [{ file: endpoint.file, line: endpoint.line }],
            evidence: [`${endpoint.method} ${endpoint.path} at ${file}:${endpoint.line}`],
            recommendation: 'Add authentication middleware to protect this endpoint.',
            references: ['https://owasp.org/API-Security/attacks/'],
            scanner: 'APIDiscoveryScanner',
          }));
        }

        if (endpoint.hasAuth && !endpoint.hasAuthz && !endpoint.isPublic) {
          this.findingCounter++;
          findings.push(createFinding({
            id: `LUI-API-${String(this.findingCounter).padStart(3, '0')}`,
            title: `Endpoint missing authorization: ${endpoint.method} ${endpoint.path}`,
            severity: 'LOW',
            confidence: 'LOW',
            category: 'API Security',
            type: 'heuristic',
            description: `The ${endpoint.method} ${endpoint.path} has authentication but no visible authorization check.`,
            impact: 'Authenticated users may access resources they should not.',
            affectedFiles: [{ file: endpoint.file, line: endpoint.line }],
            evidence: [`${endpoint.method} ${endpoint.path} at ${file}:${endpoint.line}`],
            recommendation: 'Add role-based access control or ownership checks.',
            references: ['https://owasp.org/API-Security/errors/'],
            scanner: 'APIDiscoveryScanner',
          }));
        }
      }

      this.cacheEndpointSummary(context, file, fileEndpoints);
    }

    return findings;
  }

  private extractEndpoints(lines: string[], file: string): EndpointInfo[] {
    const endpoints: EndpointInfo[] = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      for (const pattern of ROUTE_PATTERNS) {
        pattern.lastIndex = 0;
        const match = pattern.exec(line);
        if (match) {
          const routePath = match[1];
          const methodMatch = line.match(/\.((?:get|post|put|delete|patch|options|head))\s*\(/i);
          const method = methodMatch ? methodMatch[1].toUpperCase() : 'ANY';

          const contextWindow = lines.slice(Math.max(0, i - 10), Math.min(lines.length, i + 10)).join('\n');

          const hasAuth = AUTH_MIDDLEWARE.some(p => p.test(contextWindow));
          const hasAuthz = AUTHZ_MIDDLEWARE.some(p => p.test(contextWindow));
          const hasValidation = VALIDATION_PATTERNS.some(p => p.test(contextWindow));
          const isPublic = PUBLIC_PATHS.some(p => p.test(routePath));

          endpoints.push({
            method,
            path: routePath,
            file,
            line: i + 1,
            hasAuth,
            hasAuthz,
            hasValidation,
            isPublic,
          });
        }
      }
    }

    return endpoints;
  }

  private cacheEndpointSummary(context: ScanContext, file: string, endpoints: EndpointInfo[]): void {
    if (endpoints.length === 0) return;
    const summary = endpoints.map(e => `${e.method} ${e.path}`).join('\n');
    context.fileContents.set(`__endpoints:${file}`, summary);
  }
}

export function getEndpointSummary(context: ScanContext): EndpointInfo[] {
  const endpoints: EndpointInfo[] = [];
  for (const [key, value] of context.fileContents.entries()) {
    if (key.startsWith('__endpoints:')) {
      const file = key.replace('__endpoints:', '');
      for (const line of value.split('\n')) {
        const [method, ...pathParts] = line.split(' ');
        endpoints.push({
          method,
          path: pathParts.join(' '),
          file,
          line: 0,
          hasAuth: false,
          hasAuthz: false,
          hasValidation: false,
          isPublic: false,
        });
      }
    }
  }
  return endpoints;
}

export function formatEndpointMatrix(endpoints: EndpointInfo[]): string {
  const lines: string[] = [];
  lines.push('Endpoint Security Matrix');
  lines.push('━'.repeat(60));
  lines.push('');
  lines.push('Endpoint'.padEnd(35) + 'Auth'.padEnd(8) + 'AuthZ'.padEnd(8) + 'Valid');
  lines.push('─'.repeat(60));

  for (const ep of endpoints) {
    const epStr = `${ep.method} ${ep.path}`.padEnd(35);
    const auth = ep.hasAuth ? '✓' : ep.isPublic ? 'N/A' : '✗';
    const authz = ep.hasAuthz ? '✓' : ep.hasAuth ? '⚠' : 'N/A';
    const valid = ep.hasValidation ? '✓' : '⚠';
    lines.push(`${epStr}${auth.padEnd(8)}${authz.padEnd(8)}${valid}`);
  }

  return lines.join('\n');
}
