import { BaseScanner, ScanContext } from './BaseScanner';
import { Finding, createFinding } from '../models/Finding';
import { getAllFiles, relativePath, getSnippetAt } from '../utils/fileUtils';

export class AuthorizationScanner extends BaseScanner {
  private findingCounter = 200;

  constructor() {
    super('Authorization Scanner', 'authorization', 'Analyzes authorization and access control');
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
      const lines = content.split('\n');

      // Detect IDOR patterns: route handler with param ID + database lookup without ownership check
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        
        // Express route with parameter
        if (line.match(/(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['"][^'"]*:(?:id|userId|user_id|objectId|obj_id)/i)) {
          // Check if there's a database lookup without ownership check nearby
          const context = lines.slice(Math.max(0, i - 3), Math.min(lines.length, i + 15)).join('\n');
          if ((context.includes('findById') || context.includes('.findOne') || context.includes('.find(') || context.includes('SELECT') || context.includes('query(')) &&
              !context.includes('userId') && !context.includes('user_id') && !context.includes('owner') && !context.includes('createdBy') && !context.includes('permission') && !context.includes('authorize')) {
            this.findingCounter++;
            findings.push(createFinding({
              id: `LUI-AUTHZ-${String(this.findingCounter).padStart(3, '0')}`,
              title: 'Potential IDOR/BOLA vulnerability',
              severity: 'HIGH',
              confidence: 'MEDIUM',
              category: 'Authorization',
              type: 'potential',
              description: 'A route handler accepts an object ID parameter and performs a database lookup without an apparent ownership or permission check.',
              impact: 'An attacker could access or modify any object by changing the ID parameter.',
              affectedFiles: [{ file: relPath, line: i + 1, snippet: getSnippetAt(content, i + 1, 2) }],
              evidence: ['Route parameter + database lookup without ownership check'],
              recommendation: 'Implement ownership verification. Ensure the authenticated user has permission to access the requested resource.',
              cwe: 'CWE-639',
              status: 'open',
              scanner: 'AuthorizationScanner',
              timestamp: Date.now(),
            }));
          }
        }

        // Admin route without middleware
        if (line.match(/(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['"]\/admin/i)) {
          const context = lines.slice(Math.max(0, i - 3), Math.min(lines.length, i + 5)).join('\n');
          if (!context.includes('middleware') && !context.includes('auth') && !context.includes('protect') && !context.includes('guard') && !context.includes('isAdmin') && !context.includes('role')) {
            this.findingCounter++;
            findings.push(createFinding({
              id: `LUI-AUTHZ-${String(this.findingCounter).padStart(3, '0')}`,
              title: 'Admin route without authentication middleware',
              severity: 'HIGH',
              confidence: 'MEDIUM',
              category: 'Authorization',
              type: 'potential',
              description: 'An admin route appears to be accessible without authentication or authorization middleware.',
              impact: 'Unprotected admin routes could allow unauthorized access to administrative functions.',
              affectedFiles: [{ file: relPath, line: i + 1, snippet: getSnippetAt(content, i + 1, 1) }],
              evidence: ['Admin route without auth middleware'],
              recommendation: 'Add authentication and authorization middleware to all admin routes.',
              cwe: 'CWE-862',
              status: 'open',
              scanner: 'AuthorizationScanner',
              timestamp: Date.now(),
            }));
          }
        }

        // Direct user input in database query
        if (line.match(/(?:query|execute)\s*\(\s*['"][^'"]*(?:WHERE|where)[^'"]*\+/i)) {
          const context = lines.slice(Math.max(0, i - 5), Math.min(lines.length, i + 5)).join('\n');
          if (!context.includes('isAdmin') && !context.includes('role') && !context.includes('permission') && !context.includes('auth')) {
            // This is covered by SAST but we add an auth-specific finding
          }
        }
      }
    }

    return findings;
  }
}
