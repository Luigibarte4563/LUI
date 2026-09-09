import * as fs from 'fs';
import * as path from 'path';
import { analyzeDataFlows, applyTaintConfidence, collectTaintedVariables, matchSink } from '../src/analysis/DataFlow';
import { createFinding } from '../src/models/Finding';
import { ProjectDiscovery } from '../src/discovery/ProjectDiscovery';
import { SecurityAgent } from '../src/agent/SecurityAgent';
import { ConfigLoader } from '../src/config/ConfigLoader';

const FIXTURES_PATH = path.join(__dirname, 'fixtures', 'vulnerable-node');
const SERVER_PATH = path.join(FIXTURES_PATH, 'server.js');

function serverContent(): string {
  return fs.readFileSync(SERVER_PATH, 'utf-8');
}

describe('Data flow analysis', () => {
  test('collects tainted variables assigned from request input', () => {
    const variables = collectTaintedVariables(serverContent());
    expect(variables).toContain('userId');
    expect(variables).toContain('searchTerm');
    expect(variables).toContain('host');
    expect(variables).toContain('filePath');
  });

  test('identifies sinks on vulnerable lines', () => {
    const content = serverContent();
    const lines = content.split('\n');
    expect(matchSink(lines[18])?.name).toBe('SQL Injection');
    expect(matchSink(lines[28])?.name).toBe('Reflected XSS');
    expect(matchSink(lines[35])?.name).toBe('Command Injection');
    expect(matchSink(lines[88])?.name).toBe('Path Traversal');
  });

  test('detects source-to-sink data flows', () => {
    const findings = [
      createFinding({
        id: 'LUI-CODE-100',
        title: 'SQL Injection (String Concatenation)',
        severity: 'HIGH',
        category: 'Injection',
        description: 'test',
        affectedFiles: [{ file: 'server.js', line: 19 }],
        scanner: 'SASTScanner',
      }),
      createFinding({
        id: 'LUI-CODE-101',
        title: 'Reflected XSS',
        severity: 'HIGH',
        category: 'XSS',
        description: 'test',
        affectedFiles: [{ file: 'server.js', line: 29 }],
        scanner: 'SASTScanner',
      }),
    ];

    const flows = analyzeDataFlows(findings, FIXTURES_PATH, (file) => {
      return file === 'server.js' ? serverContent() : null;
    });

    expect(flows.length).toBe(2);
    expect(flows[0].file).toBe('server.js');
    expect(flows[0].variables).toContain('userId');

    const upgraded = applyTaintConfidence(findings, flows);
    expect(upgraded[0].type).toBe('confirmed');
    expect(upgraded[0].evidence.some(e => e.includes('Data flow confirmed'))).toBe(true);
  });

  test('does not invent flows where no source exists', () => {
    const benignContent = `
const x = 42;
db.query('SELECT * FROM users WHERE id = ' + x);
`;
    const findings = [
      createFinding({
        id: 'LUI-CODE-200',
        title: 'SQL Injection',
        severity: 'HIGH',
        category: 'Injection',
        description: 'test',
        affectedFiles: [{ file: 'benign.js', line: 3 }],
        scanner: 'SASTScanner',
      }),
    ];

    const flows = analyzeDataFlows(findings, FIXTURES_PATH, (file) => {
      return file === 'benign.js' ? benignContent : null;
    });

    expect(flows).toHaveLength(0);
  });
});

describe('Data flow integration with SecurityAgent', () => {
  test('attaches data flow analysis and upgrades the SQLi finding', async () => {
    const configLoader = new ConfigLoader(FIXTURES_PATH);
    const discovery = new ProjectDiscovery(FIXTURES_PATH, configLoader.getExcludes());
    const project = await discovery.discover();

    const agent = new SecurityAgent(project);
    const result = await agent.scan({ scanType: 'deep' });

    const sqli = result.findings.find(f => f.title.includes('SQL Injection'));
    expect(sqli).toBeDefined();
    expect(sqli!.type).toBe('confirmed');
    expect(sqli!.evidence.some(e => e.includes('Data flow confirmed'))).toBe(true);

    const flows = result.metadata.dataFlows as Array<{ sink: string; file: string }>;
    expect(flows.length).toBeGreaterThan(0);
    expect(flows.some(f => f.file === 'server.js')).toBe(true);
  });
});