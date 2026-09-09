import * as path from 'path';
import { DockerScanner } from '../src/scanners/DockerScanner';
import { ScanContext } from '../src/scanners/BaseScanner';

const FIXTURES_PATH = path.join(__dirname, 'fixtures', 'vulnerable-node');

function createMockContext(rootPath: string): ScanContext {
  return {
    project: {
      rootPath,
      projectName: 'test',
      technology: {
        languages: ['JavaScript'],
        frameworks: [],
        databases: [],
        authMethods: [],
        deployment: ['Docker'],
        frontend: [],
        backend: [],
        infrastructure: ['Docker'],
        packageManagers: ['npm'],
        raw: {},
      },
      hasPackageJson: false,
      hasDockerfile: true,
      hasDockerCompose: true,
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

describe('DockerScanner', () => {
  let scanner: DockerScanner;

  beforeEach(() => {
    scanner = new DockerScanner();
  });

  test('detects running as root', async () => {
    const context = createMockContext(FIXTURES_PATH);
    const findings = await scanner.scan(context);
    
    const rootFindings = findings.filter(f => f.title.includes('root'));
    expect(rootFindings.length).toBeGreaterThan(0);
  });

  test('detects privileged mode in docker-compose', async () => {
    const context = createMockContext(FIXTURES_PATH);
    const findings = await scanner.scan(context);
    
    const privFindings = findings.filter(f => f.title.includes('privileged'));
    expect(privFindings.length).toBeGreaterThan(0);
  });

  test('detects host network mode', async () => {
    const context = createMockContext(FIXTURES_PATH);
    const findings = await scanner.scan(context);
    
    const hostFindings = findings.filter(f => f.title.includes('host network'));
    expect(hostFindings.length).toBeGreaterThan(0);
  });

  test('detects dangerous port exposure', async () => {
    const context = createMockContext(FIXTURES_PATH);
    const findings = await scanner.scan(context);
    
    const portFindings = findings.filter(f => f.title.includes('Dangerous port'));
    expect(portFindings.length).toBeGreaterThan(0);
  });

  test('detects secrets in docker-compose', async () => {
    const context = createMockContext(FIXTURES_PATH);
    const findings = await scanner.scan(context);
    
    const secretFindings = findings.filter(f => f.title.includes('secret') || f.title.includes('Secret'));
    expect(secretFindings.length).toBeGreaterThan(0);
  });
});
