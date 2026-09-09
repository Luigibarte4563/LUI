import { BaseScanner, ScanContext } from './BaseScanner';
import { Finding, createFinding } from '../models/Finding';
import { relativePath, readFileSafe, getAllFiles } from '../utils/fileUtils';
import * as path from 'path';
import * as fs from 'fs';

export class DockerScanner extends BaseScanner {
  private findingCounter = 500;

  constructor() {
    super('Docker Scanner', 'docker', 'Analyzes Docker configuration for security issues');
  }

  async scan(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Scan Dockerfile
    const dockerfilePath = path.join(context.rootPath, 'Dockerfile');
    if (fs.existsSync(dockerfilePath)) {
      findings.push(...this.scanDockerfile(context, dockerfilePath));
    }

    // Scan docker-compose files
    const composeFiles = ['docker-compose.yml', 'docker-compose.yaml', 'docker-compose.override.yml'];
    for (const file of composeFiles) {
      const composePath = path.join(context.rootPath, file);
      if (fs.existsSync(composePath)) {
        findings.push(...this.scanDockerCompose(context, composePath));
      }
    }

    return findings;
  }

  private scanDockerfile(context: ScanContext, dockerfilePath: string): Finding[] {
    const findings: Finding[] = [];
    const content = readFileSafe(dockerfilePath);
    if (!content) return findings;
    const relPath = relativePath(dockerfilePath, context.rootPath);
    const lines = content.split('\n');

    let hasUserDirective = false;
    let hasHealthCheck = false;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line || line.startsWith('#')) continue;

      // Running as root
      if (line.startsWith('USER')) {
        hasUserDirective = true;
        if (line.includes('root')) {
          this.findingCounter++;
          findings.push(createFinding({
            id: `LUI-DKR-${String(this.findingCounter).padStart(3, '0')}`,
            title: 'Container runs as root',
            severity: 'HIGH',
            confidence: 'HIGH',
            category: 'Docker Security',
            type: 'confirmed',
            description: 'The Dockerfile explicitly sets the user to root.',
            impact: 'Running as root increases the impact of container escape vulnerabilities.',
            affectedFiles: [{ file: relPath, line: i + 1 }],
            evidence: [line],
            recommendation: 'Use a non-root user with the least privileges necessary.',
            cwe: 'CWE-250',
            status: 'open',
            scanner: 'DockerScanner',
            timestamp: Date.now(),
          }));
        }
      }

      if (line.startsWith('HEALTHCHECK')) hasHealthCheck = true;

      // Secrets in ENV
      if (line.startsWith('ENV')) {
        const envMatch = line.match(/ENV\s+(\w+)\s*=\s*(.+)/i);
        if (envMatch) {
          const [, key, value] = envMatch;
          const sensitiveKeys = ['PASSWORD', 'SECRET', 'TOKEN', 'KEY', 'API_KEY', 'CREDENTIAL'];
          if (sensitiveKeys.some(sk => key.toUpperCase().includes(sk)) && value.length > 2) {
            this.findingCounter++;
            findings.push(createFinding({
              id: `LUI-DKR-${String(this.findingCounter).padStart(3, '0')}`,
              title: 'Secret in Dockerfile ENV',
              severity: 'CRITICAL',
              confidence: 'HIGH',
              category: 'Docker Security',
              type: 'confirmed',
              description: `A secret (${key}) is hardcoded in the Dockerfile ENV directive.`,
              impact: 'Secrets in Docker images are visible to anyone who pulls or inspects the image.',
              affectedFiles: [{ file: relPath, line: i + 1 }],
              evidence: [line],
              recommendation: 'Use Docker secrets, build-time secrets, or runtime environment variables instead.',
              cwe: 'CWE-798',
              status: 'open',
              scanner: 'DockerScanner',
              timestamp: Date.now(),
            }));
          }
        }
      }

      // Secrets in COPY or ADD
      if ((line.startsWith('COPY') || line.startsWith('ADD')) && 
          (line.includes('.env') || line.includes('credentials') || line.includes('.key') || line.includes('.pem'))) {
        this.findingCounter++;
        findings.push(createFinding({
          id: `LUI-DKR-${String(this.findingCounter).padStart(3, '0')}`,
          title: 'Sensitive file copied to image',
          severity: 'HIGH',
          confidence: 'HIGH',
          category: 'Docker Security',
          type: 'confirmed',
          description: 'A sensitive file is being copied into the Docker image.',
          impact: 'Sensitive files in the image can be extracted by anyone with access to the image.',
          affectedFiles: [{ file: relPath, line: i + 1 }],
          evidence: [line],
          recommendation: 'Do not copy sensitive files into Docker images. Use Docker secrets or mounted volumes.',
          cwe: 'CWE-312',
          status: 'open',
          scanner: 'DockerScanner',
          timestamp: Date.now(),
        }));
      }

      // Using latest tag
      if (line.startsWith('FROM') && line.includes(':latest')) {
        this.findingCounter++;
        findings.push(createFinding({
          id: `LUI-DKR-${String(this.findingCounter).padStart(3, '0')}`,
          title: 'Using :latest base image tag',
          severity: 'LOW',
          confidence: 'HIGH',
          category: 'Docker Security',
          type: 'confirmed',
          description: 'The Dockerfile uses the :latest tag for the base image.',
          impact: 'Using :latest can lead to unexpected changes and makes builds non-reproducible.',
          affectedFiles: [{ file: relPath, line: i + 1 }],
          evidence: [line],
          recommendation: 'Pin base images to specific version tags or SHA256 digests.',
          cwe: 'CWE-1104',
          status: 'open',
          scanner: 'DockerScanner',
          timestamp: Date.now(),
        }));
      }

      // EXPOSE high ports
      if (line.startsWith('EXPOSE')) {
        const portMatch = line.match(/EXPOSE\s+(\d+)/);
        if (portMatch) {
          const port = parseInt(portMatch[1]);
          if (port === 22 || port === 23 || port === 3389 || port === 445) {
            this.findingCounter++;
            findings.push(createFinding({
              id: `LUI-DKR-${String(this.findingCounter).padStart(3, '0')}`,
              title: `Dangerous port exposed: ${port}`,
              severity: 'MEDIUM',
              confidence: 'HIGH',
              category: 'Docker Security',
              type: 'confirmed',
              description: `Port ${port} is exposed in the Dockerfile, which is typically associated with insecure services.`,
              impact: `Exposing port ${port} could allow unauthorized access to the service.`,
              affectedFiles: [{ file: relPath, line: i + 1 }],
              evidence: [line],
              recommendation: `Avoid exposing port ${port} unless absolutely necessary.`,
              cwe: 'CWE-284',
              status: 'open',
              scanner: 'DockerScanner',
              timestamp: Date.now(),
            }));
          }
        }
      }
    }

    // Check for missing USER directive (runs as root by default)
    if (!hasUserDirective) {
      this.findingCounter++;
      findings.push(createFinding({
        id: `LUI-DKR-${String(this.findingCounter).padStart(3, '0')}`,
        title: 'Container runs as root (no USER directive)',
        severity: 'HIGH',
        confidence: 'HIGH',
        category: 'Docker Security',
        type: 'confirmed',
        description: 'The Dockerfile does not specify a USER directive, so the container will run as root.',
        impact: 'Running as root increases the impact of container escape vulnerabilities.',
        affectedFiles: [{ file: relPath }],
        evidence: ['No USER directive found'],
        recommendation: 'Add a USER directive to run the container as a non-root user.',
        cwe: 'CWE-250',
        status: 'open',
        scanner: 'DockerScanner',
        timestamp: Date.now(),
      }));
    }

    return findings;
  }

  private scanDockerCompose(context: ScanContext, composePath: string): Finding[] {
    const findings: Finding[] = [];
    const content = readFileSafe(composePath);
    if (!content) return findings;
    const relPath = relativePath(composePath, context.rootPath);

    // Check for privileged mode
    if (content.includes('privileged: true')) {
      this.findingCounter++;
      const line = this.getLineNumber(content, 'privileged: true');
      findings.push(createFinding({
        id: `LUI-DKR-${String(this.findingCounter).padStart(3, '0')}`,
        title: 'Container runs in privileged mode',
        severity: 'CRITICAL',
        confidence: 'HIGH',
        category: 'Docker Security',
        type: 'confirmed',
        description: 'A container is configured to run in privileged mode.',
        impact: 'Privileged containers have full access to the host, making container escape trivial.',
        affectedFiles: [{ file: relPath, line }],
        evidence: ['privileged: true'],
        recommendation: 'Remove privileged mode. Use specific Linux capabilities instead.',
        cwe: 'CWE-250',
        status: 'open',
        scanner: 'DockerScanner',
        timestamp: Date.now(),
      }));
    }

    // Check for host network
    if (content.includes('network_mode: host')) {
      this.findingCounter++;
      const line = this.getLineNumber(content, 'network_mode: host');
      findings.push(createFinding({
        id: `LUI-DKR-${String(this.findingCounter).padStart(3, '0')}`,
        title: 'Container uses host network',
        severity: 'MEDIUM',
        confidence: 'HIGH',
        category: 'Docker Security',
        type: 'confirmed',
        description: 'A container is configured to use the host network namespace.',
        impact: 'Host network mode bypasses network isolation and can expose host services.',
        affectedFiles: [{ file: relPath, line }],
        evidence: ['network_mode: host'],
        recommendation: 'Use bridge networking with explicit port mappings instead.',
        cwe: 'CWE-668',
        status: 'open',
        scanner: 'DockerScanner',
        timestamp: Date.now(),
      }));
    }

    // Check for sensitive volume mounts
    if (content.includes('/var/run/docker.sock') || content.includes('/proc') || content.includes('/sys')) {
      this.findingCounter++;
      const line = this.getLineNumber(content, '/var/run/docker.sock') || this.getLineNumber(content, '/proc');
      findings.push(createFinding({
        id: `LUI-DKR-${String(this.findingCounter).padStart(3, '0')}`,
        title: 'Sensitive host path mounted',
        severity: 'HIGH',
        confidence: 'HIGH',
        category: 'Docker Security',
        type: 'confirmed',
        description: 'A sensitive host path is mounted into the container.',
        impact: 'Mounting sensitive host paths can allow container escape or host compromise.',
        affectedFiles: [{ file: relPath, line }],
        evidence: ['Sensitive volume mount detected'],
        recommendation: 'Avoid mounting sensitive host paths. Use Docker volumes or secrets instead.',
        cwe: 'CWE-284',
        status: 'open',
        scanner: 'DockerScanner',
        timestamp: Date.now(),
      }));
    }

    // Check for environment secrets in compose
    const envLines = content.split('\n');
    for (let i = 0; i < envLines.length; i++) {
      const line = envLines[i];
      if (line.match(/^\s+(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)\s*[:=]/i)) {
        this.findingCounter++;
        findings.push(createFinding({
          id: `LUI-DKR-${String(this.findingCounter).padStart(3, '0')}`,
          title: 'Secret in docker-compose environment',
          severity: 'HIGH',
          confidence: 'HIGH',
          category: 'Docker Security',
          type: 'confirmed',
          description: 'A secret is hardcoded in the docker-compose environment configuration.',
          impact: 'Secrets in docker-compose files are visible to anyone with access to the file.',
          affectedFiles: [{ file: relPath, line: i + 1 }],
          evidence: [line.trim()],
          recommendation: 'Use Docker secrets or .env files (with .gitignore) for sensitive values.',
          cwe: 'CWE-798',
          status: 'open',
          scanner: 'DockerScanner',
          timestamp: Date.now(),
        }));
      }
    }

    return findings;
  }
}
