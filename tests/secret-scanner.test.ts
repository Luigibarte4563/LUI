import * as path from 'path';
import { SecretScanner } from '../src/scanners/SecretScanner';
import { ScanContext } from '../src/scanners/BaseScanner';
import { ProjectProfile } from '../src/models/ProjectProfile';

const FIXTURES_PATH = path.join(__dirname, 'fixtures', 'vulnerable-node');

function createMockContext(rootPath: string): ScanContext {
  return {
    project: {
      rootPath,
      projectName: 'test',
      technology: {
        languages: ['JavaScript'],
        frameworks: ['Express'],
        databases: ['MySQL'],
        authMethods: [],
        deployment: ['Docker'],
        frontend: [],
        backend: ['Express'],
        infrastructure: ['Docker'],
        packageManagers: ['npm'],
        raw: {},
      },
      hasPackageJson: true,
      hasDockerfile: true,
      hasDockerCompose: false,
      hasCICD: false,
      hasGit: false,
      hasDotEnv: true,
      hasPython: false,
      hasNode: true,
      hasPHP: false,
      hasJava: false,
      hasGo: false,
      hasRust: false,
      hasRuby: false,
      hasDotNet: false,
      fileCount: 10,
      sourceFiles: [],
      configFiles: [],
      infrastructureFiles: [],
      sensitiveFiles: [],
      totalSize: 1000,
    },
    rootPath,
    scanType: 'standard',
    config: { exclude: ['node_modules'] },
    fileContents: new Map(),
  };
}

describe('SecretScanner', () => {
  let scanner: SecretScanner;

  beforeEach(() => {
    scanner = new SecretScanner();
  });

  test('detects secrets in .env files', async () => {
    const context = createMockContext(FIXTURES_PATH);
    const findings = await scanner.scan(context);
    
    expect(findings.length).toBeGreaterThan(0);
    
    const envFindings = findings.filter(f => 
      f.affectedFiles.some(af => af.file.includes('.env'))
    );
    expect(envFindings.length).toBeGreaterThan(0);
  });

  test('detects hardcoded secrets in source code', async () => {
    const context = createMockContext(FIXTURES_PATH);
    const findings = await scanner.scan(context);
    
    const sourceFindings = findings.filter(f => 
      f.affectedFiles.some(af => af.file.includes('server.js'))
    );
    expect(sourceFindings.length).toBeGreaterThan(0);
  });

  test('masks secret values in output', async () => {
    const context = createMockContext(FIXTURES_PATH);
    const findings = await scanner.scan(context);
    
    for (const finding of findings) {
      for (const evidence of finding.evidence) {
        // Should not contain full secrets
        expect(evidence).not.toContain('password123');
        expect(evidence).not.toContain('super_secret_key_12345');
      }
    }
  });

  test('returns empty for project with no secrets', async () => {
    const securePath = path.join(__dirname, 'fixtures', 'secure-project');
    const context = createMockContext(securePath);
    const findings = await scanner.scan(context);
    
    const secretFindings = findings.filter(f => f.category === 'Secrets');
    expect(secretFindings.length).toBe(0);
  });
});
