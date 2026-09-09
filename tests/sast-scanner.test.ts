import * as path from 'path';
import { SASTScanner } from '../src/scanners/SASTScanner';
import { ScanContext } from '../src/scanners/BaseScanner';

const FIXTURES_PATH = path.join(__dirname, 'fixtures', 'vulnerable-node');

function createMockContext(rootPath: string): ScanContext {
  return {
    project: {
      rootPath,
      projectName: 'test',
      technology: {
        languages: ['JavaScript'],
        frameworks: ['Express'],
        databases: [],
        authMethods: [],
        deployment: [],
        frontend: [],
        backend: ['Express'],
        infrastructure: [],
        packageManagers: ['npm'],
        raw: {},
      },
      hasPackageJson: true,
      hasDockerfile: false,
      hasDockerCompose: false,
      hasCICD: false,
      hasGit: false,
      hasDotEnv: false,
      hasPython: false,
      hasNode: true,
      hasPHP: false,
      hasJava: false,
      hasGo: false,
      hasRust: false,
      hasRuby: false,
      hasDotNet: false,
      fileCount: 5,
      sourceFiles: [],
      configFiles: [],
      infrastructureFiles: [],
      sensitiveFiles: [],
      totalSize: 500,
    },
    rootPath,
    scanType: 'standard',
    config: { exclude: ['node_modules'] },
    fileContents: new Map(),
  };
}

describe('SASTScanner', () => {
  let scanner: SASTScanner;

  beforeEach(() => {
    scanner = new SASTScanner();
  });

  test('detects SQL injection patterns', async () => {
    const context = createMockContext(FIXTURES_PATH);
    const findings = await scanner.scan(context);
    
    const sqliFindings = findings.filter(f => f.title.includes('SQL Injection'));
    expect(sqliFindings.length).toBeGreaterThan(0);
  });

  test('detects XSS patterns', async () => {
    const context = createMockContext(FIXTURES_PATH);
    const findings = await scanner.scan(context);
    
    const xssFindings = findings.filter(f => f.category === 'XSS');
    expect(xssFindings.length).toBeGreaterThan(0);
  });

  test('detects command injection', async () => {
    const context = createMockContext(FIXTURES_PATH);
    const findings = await scanner.scan(context);
    
    const cmdiFindings = findings.filter(f => f.title.includes('Command Injection'));
    expect(cmdiFindings.length).toBeGreaterThan(0);
  });

  test('detects path traversal', async () => {
    const context = createMockContext(FIXTURES_PATH);
    const findings = await scanner.scan(context);
    
    const pathFindings = findings.filter(f => f.title.includes('Path Traversal'));
    expect(pathFindings.length).toBeGreaterThan(0);
  });

  test('detects weak cryptography', async () => {
    const context = createMockContext(FIXTURES_PATH);
    const findings = await scanner.scan(context);
    
    const cryptoFindings = findings.filter(f => f.category === 'Cryptography');
    expect(cryptoFindings.length).toBeGreaterThan(0);
  });

  test('returns fewer findings for secure project', async () => {
    const securePath = path.join(__dirname, 'fixtures', 'secure-project');
    const context = createMockContext(securePath);
    const findings = await scanner.scan(context);
    
    // Secure project should have fewer SAST findings
    expect(findings.length).toBeLessThan(5);
  });
});
