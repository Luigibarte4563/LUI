import * as path from 'path';
import { DependencyScanner } from '../src/scanners/DependencyScanner';
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

describe('DependencyScanner', () => {
  let scanner: DependencyScanner;

  beforeEach(() => {
    scanner = new DependencyScanner();
  });

  test('detects vulnerable dependencies', async () => {
    const context = createMockContext(FIXTURES_PATH);
    const findings = await scanner.scan(context);
    
    expect(findings.length).toBeGreaterThan(0);
    
    const depFindings = findings.filter(f => f.category === 'Dependencies');
    expect(depFindings.length).toBeGreaterThan(0);
  });

  test('identifies specific vulnerable packages', async () => {
    const context = createMockContext(FIXTURES_PATH);
    const findings = await scanner.scan(context);
    
    const lodashFinding = findings.find(f => f.title.includes('lodash'));
    expect(lodashFinding).toBeDefined();
    expect(lodashFinding!.severity).toBe('HIGH');
  });

  test('returns findings for package.json', async () => {
    const context = createMockContext(FIXTURES_PATH);
    const findings = await scanner.scan(context);
    
    const packageFindings = findings.filter(f => 
      f.affectedFiles.some(af => af.file.includes('package.json'))
    );
    expect(packageFindings.length).toBeGreaterThan(0);
  });
});
