import { BaseScanner, ScanContext } from './BaseScanner';
import { Finding, createFinding } from '../models/Finding';
import { relativePath, readFileSafe, getAllFiles } from '../utils/fileUtils';
import * as path from 'path';
import * as fs from 'fs';

export class CICDScanner extends BaseScanner {
  private findingCounter = 600;

  constructor() {
    super('CI/CD Scanner', 'cicd', 'Analyzes CI/CD configuration for security issues');
  }

  async scan(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Scan GitHub Actions
    const ghWorkflowsPath = path.join(context.rootPath, '.github', 'workflows');
    if (fs.existsSync(ghWorkflowsPath)) {
      findings.push(...this.scanGitHubActions(context, ghWorkflowsPath));
    }

    // Scan GitLab CI
    const gitlabCIPath = path.join(context.rootPath, '.gitlab-ci.yml');
    if (fs.existsSync(gitlabCIPath)) {
      findings.push(...this.scanGitLabCI(context, gitlabCIPath));
    }

    return findings;
  }

  private scanGitHubActions(context: ScanContext, workflowsDir: string): Finding[] {
    const findings: Finding[] = [];
    const workflowFiles = getAllFiles(workflowsDir, ['.yml', '.yaml']);

    for (const workflowPath of workflowFiles) {
      const content = readFileSafe(workflowPath);
      if (!content) continue;
      const relPath = relativePath(workflowPath, context.rootPath);

      // Check for pull_request_target
      if (content.includes('pull_request_target')) {
        this.findingCounter++;
        const line = this.getLineNumber(content, 'pull_request_target');
        findings.push(createFinding({
          id: `LUI-CICD-${String(this.findingCounter).padStart(3, '0')}`,
          title: 'Unsafe use of pull_request_target',
          severity: 'HIGH',
          confidence: 'HIGH',
          category: 'CI/CD Security',
          type: 'confirmed',
          description: 'The workflow uses pull_request_target, which runs with write access to the repository.',
          impact: 'A malicious pull request could modify the workflow or execute arbitrary code with write permissions.',
          affectedFiles: [{ file: relPath, line }],
          evidence: ['pull_request_target trigger detected'],
          recommendation: 'Use pull_request instead, or carefully restrict what the pull_request_target workflow can do.',
          cwe: 'CWE-829',
          status: 'open',
          scanner: 'CICDScanner',
          timestamp: Date.now(),
        }));
      }

      // Check for unpinned actions
      const actionMatches = content.matchAll(/uses:\s*([^@\s]+)@(?!(?:[a-f0-9]{40}|[a-f0-9]{64}))/gi);
      for (const match of actionMatches) {
        const action = match[1];
        if (action.includes('/')) {
          this.findingCounter++;
          const line = this.getLineNumber(content, match[0]);
          findings.push(createFinding({
            id: `LUI-CICD-${String(this.findingCounter).padStart(3, '0')}`,
            title: `Unpinned GitHub Action: ${action}`,
            severity: 'MEDIUM',
            confidence: 'HIGH',
            category: 'CI/CD Security',
            type: 'confirmed',
            description: `GitHub Action ${action} is not pinned to a specific commit SHA.`,
            impact: 'An attacker who compromises the action repository could inject malicious code.',
            affectedFiles: [{ file: relPath, line }],
            evidence: [`Action: ${match[0]}`],
            recommendation: 'Pin actions to full commit SHAs instead of tags.',
            cwe: 'CWE-829',
            status: 'open',
            scanner: 'CICDScanner',
            timestamp: Date.now(),
          }));
          break; // One finding per file is enough
        }
      }

      // Check for excessive permissions
      if (content.includes('permissions:') && content.includes('write-all')) {
        this.findingCounter++;
        const line = this.getLineNumber(content, 'write-all');
        findings.push(createFinding({
          id: `LUI-CICD-${String(this.findingCounter).padStart(3, '0')}`,
          title: 'Excessive workflow permissions',
          severity: 'HIGH',
          confidence: 'HIGH',
          category: 'CI/CD Security',
          type: 'confirmed',
          description: 'The workflow requests write-all permissions.',
          impact: 'Excessive permissions increase the impact of a compromised workflow.',
          affectedFiles: [{ file: relPath, line }],
          evidence: ['permissions: write-all'],
          recommendation: 'Request only the minimum permissions needed. Use specific permission scopes.',
          cwe: 'CWE-269',
          status: 'open',
          scanner: 'CICDScanner',
          timestamp: Date.now(),
        }));
      }

      // Check for secrets in environment
      if (content.match(/run:\s*\|?[\s\S]*\$\{\{.*SECRET/gi)) {
        this.findingCounter++;
        const line = this.getLineNumber(content, 'SECRET');
        findings.push(createFinding({
          id: `LUI-CICD-${String(this.findingCounter).padStart(3, '0')}`,
          title: 'Potential secret exposure in workflow',
          severity: 'HIGH',
          confidence: 'MEDIUM',
          category: 'CI/CD Security',
          type: 'potential',
          description: 'A secret may be exposed in a workflow step.',
          impact: 'Secrets in logs or output can be accessed by anyone with read access to the repository.',
          affectedFiles: [{ file: relPath, line }],
          evidence: ['Secret used in run step'],
          recommendation: 'Use environment variables for secrets. Never echo or print secrets.',
          cwe: 'CWE-200',
          status: 'open',
          scanner: 'CICDScanner',
          timestamp: Date.now(),
        }));
      }

      // Check for unsafe script execution
      if (content.match(/run:\s*\|?[\s\S]*\$\{\{.*github\.event\.pull_request\.(title|body|head\.ref)/gi)) {
        this.findingCounter++;
        const line = this.getLineNumber(content, 'github.event.pull_request');
        findings.push(createFinding({
          id: `LUI-CICD-${String(this.findingCounter).padStart(3, '0')}`,
          title: 'Untrusted input in workflow script',
          severity: 'HIGH',
          confidence: 'MEDIUM',
          category: 'CI/CD Security',
          type: 'potential',
          description: 'User-controlled pull request data is used in a workflow script.',
          impact: 'A malicious pull request could inject arbitrary code into the workflow.',
          affectedFiles: [{ file: relPath, line }],
          evidence: ['Pull request data used in run step'],
          recommendation: 'Sanitize user input before using it in scripts. Avoid directly interpolating PR data.',
          cwe: 'CWE-78',
          status: 'open',
          scanner: 'CICDScanner',
          timestamp: Date.now(),
        }));
      }
    }

    return findings;
  }

  private scanGitLabCI(context: ScanContext, gitlabCIPath: string): Finding[] {
    const findings: Finding[] = [];
    const content = readFileSafe(gitlabCIPath);
    if (!content) return findings;
    const relPath = relativePath(gitlabCIPath, context.rootPath);

    // Check for secrets in variables
    if (content.match(/variables:[\s\S]*(?:PASSWORD|SECRET|TOKEN|API_KEY)\s*:/gi)) {
      this.findingCounter++;
      const line = this.getLineNumber(content, 'variables');
      findings.push(createFinding({
        id: `LUI-CICD-${String(this.findingCounter).padStart(3, '0')}`,
        title: 'Potential secret in GitLab CI variables',
        severity: 'HIGH',
        confidence: 'MEDIUM',
        category: 'CI/CD Security',
        type: 'potential',
        description: 'A sensitive variable may be hardcoded in the GitLab CI configuration.',
        impact: 'Hardcoded secrets in CI/CD files are visible to anyone with repository access.',
        affectedFiles: [{ file: relPath, line }],
        evidence: ['Sensitive variable in CI config'],
        recommendation: 'Use GitLab CI/CD variables with masked and protected settings.',
        cwe: 'CWE-798',
        status: 'open',
        scanner: 'CICDScanner',
        timestamp: Date.now(),
      }));
    }

    // Check for before_script that fetches from external sources
    if (content.includes('before_script') && content.includes('curl') && (content.includes('bash') || content.includes('sh'))) {
      this.findingCounter++;
      const line = this.getLineNumber(content, 'before_script');
      findings.push(createFinding({
        id: `LUI-CICD-${String(this.findingCounter).padStart(3, '0')}`,
        title: 'External script execution in CI/CD',
        severity: 'MEDIUM',
        confidence: 'MEDIUM',
        category: 'CI/CD Security',
        type: 'potential',
        description: 'A script is being downloaded and executed in the CI/CD pipeline.',
        impact: 'If the external source is compromised, malicious code could be executed in the pipeline.',
        affectedFiles: [{ file: relPath, line }],
        evidence: ['curl | bash pattern detected'],
        recommendation: 'Verify script integrity. Pin to specific versions. Use checksums.',
        cwe: 'CWE-829',
        status: 'open',
        scanner: 'CICDScanner',
        timestamp: Date.now(),
      }));
    }

    return findings;
  }
}
