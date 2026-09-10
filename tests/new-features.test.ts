import { createFinding, Finding, Severity, Confidence, FindingType } from '../src/models/Finding';
import { buildEvidenceExplanation } from '../src/analysis/EvidenceEngine';
import { buildContextGraph } from '../src/analysis/ContextGraph';
import { prioritizeFindings } from '../src/analysis/RiskPrioritization';
import { generateSecurityTest } from '../src/analysis/TestGenerator';
import { generateRotationGuidance, formatRotationGuidance } from '../src/analysis/SecretRotation';
import { buildDependencyGraph } from '../src/analysis/DependencyGraph';
import { loadLifecycleStore, updateFindingStatus, initializeLifecycle } from '../src/analysis/Lifecycle';
import { loadPolicy, evaluatePolicy } from '../src/config/PolicyEngine';
import { getProfile, SECURITY_PROFILES } from '../src/config/Profiles';
import { createPlugin, PluginRegistry } from '../src/plugins/PluginRegistry';
import { createMCPServer } from '../src/integration/MCPIntegration';
import { buildAttackSurface } from '../src/commands/map';
import { investigateProject } from '../src/commands/investigate';
import { askLui } from '../src/commands/ask';
import { APIDiscoveryScanner } from '../src/scanners/APIDiscoveryScanner';
import * as path from 'path';

const FIXTURES_PATH = path.join(__dirname, 'fixtures', 'vulnerable-node');

function createFindingHelper(overrides: Partial<Finding> = {}): Finding {
  const defaults: Partial<Finding> = {
    id: 'LUI-SEC-001',
    title: 'Potential SQL Injection',
    severity: 'HIGH' as Severity,
    confidence: 'MEDIUM' as Confidence,
    category: 'Injection',
    description: 'User input reaches SQL query',
    affectedFiles: [{ file: 'src/index.js', line: 10 }],
  };
  return createFinding({ ...defaults, ...overrides } as any);
}

describe('Evidence Engine', () => {
  test('builds data flow explanation for injection findings', () => {
    const finding = createFindingHelper();
    const flows = [{
      source: 'req.query.search',
      sink: 'SQL query',
      file: 'src/index.js',
      sinkLine: 10,
      variables: ['search'],
      confidence: 'HIGH' as const,
    }];

    const getContent = (file: string) => {
      if (file === 'src/index.js') {
        return 'const search = req.query.search;\nconst query = "SELECT * FROM users WHERE name = " + search;\ndb.query(query);';
      }
      return null;
    };

    const explanation = buildEvidenceExplanation(finding, flows, getContent);

    expect(explanation.findingId).toBe('LUI-SEC-001');
    expect(explanation.dataFlowSteps.length).toBeGreaterThan(0);
    expect(explanation.dataFlowSteps[0].type).toBe('source');
    expect(explanation.sanitizationStatus).toBeDefined();
    expect(explanation.confidenceReason.length).toBeGreaterThan(0);
  });

  test('detects sanitization in code context', () => {
    const finding = createFindingHelper();
    const getContent = () => {
      return 'const user = sanitizeInput(req.query.id);\nconst query = "SELECT * FROM users WHERE id = " + user;\ndb.query(query);';
    };

    const explanation = buildEvidenceExplanation(finding, [], getContent);

    expect(explanation.sanitizationStatus).toBe('PARTIAL');
  });

  test('reports NOT_DETECTED when no sanitization present', () => {
    const finding = createFindingHelper();
    const getContent = () => {
      return 'const id = req.query.id;\ndb.query("SELECT * FROM users WHERE id = " + id);';
    };

    const explanation = buildEvidenceExplanation(finding, [], getContent);

    expect(explanation.sanitizationStatus).toBe('NOT_DETECTED');
  });
});

describe('Context Graph', () => {
  test('builds graph with nodes and edges from findings', () => {
    const finding = createFindingHelper({
      affectedFiles: [{ file: 'src/api/users.ts', line: 5 }],
    });

    const getContent = (file: string) => {
      if (file === 'src/api/users.ts') {
        return [
          'const userId = req.query.id;',
          'app.get("/api/users", (req, res) => {',
          '  db.query("SELECT * FROM users WHERE id = " + userId);',
          '});',
        ].join('\n');
      }
      return null;
    };

    const graph = buildContextGraph([finding], getContent);

    expect(graph.nodes.length).toBeGreaterThan(0);
    expect(graph.nodes.some(n => n.type === 'input')).toBe(true);
    expect(graph.nodes.some(n => n.type === 'output')).toBe(true);
  });

  test('identifies data flow chains', () => {
    const finding = createFindingHelper();
    const getContent = (file: string) => file.includes('server') 
      ? 'const x = req.body.name;\ndb.query("SELECT * FROM t WHERE n=" + x);'
      : null;

    const graph = buildContextGraph([finding], getContent);
    expect(graph.chains).toBeDefined();
  });
});

describe('Risk Prioritization', () => {
  test('scores critical findings as P0', () => {
    const critical = createFindingHelper({
      id: 'LUI-SEC-001',
      severity: 'CRITICAL',
      category: 'Secrets',
      confidence: 'HIGH',
      type: 'confirmed',
      affectedFiles: [{ file: 'src/app.ts', line: 10 }],
    });

    const flows = [{ source: 'x', sink: 'SQL query', file: 'src/app.ts', sinkLine: 10, variables: [], confidence: 'HIGH' as const }];
    const priorities = prioritizeFindings([critical], flows);

    expect(priorities.length).toBe(1);
    expect(priorities[0].priority).toBe('P0');
    expect(priorities[0].reasoning.length).toBeGreaterThan(0);
  });

  test('sorts findings by priority score', () => {
    const critical = createFindingHelper({
      id: 'LUI-SEC-001',
      severity: 'CRITICAL',
      category: 'Injection',
      confidence: 'HIGH',
      type: 'confirmed',
      affectedFiles: [{ file: 'a.ts', line: 1 }],
    });
    const info = createFindingHelper({
      id: 'LUI-SEC-002',
      severity: 'INFO',
      category: 'Configuration',
      confidence: 'LOW',
      type: 'heuristic',
      affectedFiles: [{ file: 'b.ts', line: 2 }],
    });

    const priorities = prioritizeFindings([info, critical], []);
    expect(priorities[0].findingId).toBe('LUI-SEC-001');
  });
});

describe('Test Generator', () => {
  test('generates SQL injection regression test', () => {
    const finding = createFindingHelper({ category: 'Injection' });
    const test = generateSecurityTest(finding);

    expect(test.findingId).toBe('LUI-SEC-001');
    expect(test.testCode).toContain('maliciousInputs');
    expect(test.testCode).toContain("' OR '1'='1");
  });

  test('generates XSS regression test', () => {
    const finding = createFindingHelper({ category: 'XSS', title: 'XSS' });
    const test = generateSecurityTest(finding);

    expect(test.description).toContain('HTML metacharacters');
  });

  test('generates secrets test', () => {
    const finding = createFindingHelper({ category: 'Secrets', title: 'API key' });
    const test = generateSecurityTest(finding);

    expect(test.testCode).toContain('No Hardcoded Secrets');
  });
});

describe('Secret Rotation Guidance', () => {
  test('generates guidance for secret findings', () => {
    const finding = createFindingHelper({
      category: 'Secrets',
      title: 'AWS Access Key',
      description: 'AWS credential detected',
    });

    const guidance = generateRotationGuidance(finding);
    expect(guidance).not.toBeNull();
    expect(guidance!.steps.length).toBeGreaterThan(0);
    expect(guidance!.gitHistoryWarning).toBe(true);
    expect(guidance!.secretType).toBe('AWS Credential');
  });

  test('returns null for non-secret findings', () => {
    const finding = createFindingHelper({ category: 'Injection' });
    const guidance = generateRotationGuidance(finding);
    expect(guidance).toBeNull();
  });
});

describe('Dependency Graph', () => {
  test('builds graph from package.json with vulnerabilities', () => {
    const finding = createFindingHelper({
      category: 'Dependencies',
      title: 'lodash vulnerable version',
    });

    const graph = buildDependencyGraph(FIXTURES_PATH, [finding]);
    expect(graph.roots.length).toBeGreaterThan(0);
  });
});

describe('Lifecycle', () => {
  test('manages finding lifecycle states', () => {
    const store = loadLifecycleStore(process.cwd());
    const updated = updateFindingStatus(store, 'LUI-SEC-001', 'new');
    awaitSleep(10);
    const confirmed = updateFindingStatus(updated, 'LUI-SEC-001', 'confirmed');
    const fixed = updateFindingStatus(confirmed, 'LUI-SEC-001', 'fixed', 'Used parameterized query');

    expect(fixed.findings['LUI-SEC-001'].status).toBe('fixed');
    expect(fixed.findings['LUI-SEC-001'].confirmedAt).toBeDefined();
    expect(fixed.findings['LUI-SEC-001'].fixedAt).toBeDefined();
    expect(fixed.findings['LUI-SEC-001'].notes.length).toBe(1);
  });

  test('initializes lifecycle for new findings', () => {
    const store = { findings: {} };
    const result = initializeLifecycle(store, ['LUI-SEC-001', 'LUI-SEC-002']);
    expect(Object.keys(result.findings).length).toBe(2);
    expect(result.findings['LUI-SEC-001'].status).toBe('new');
  });
});

function awaitSleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

describe('Policy Engine', () => {
  test('loads empty policy when no file present', () => {
    const config = loadPolicy(process.cwd());
    expect(config).toBeDefined();
  });

  test('evaluates policy violations', () => {
    const result = {
      target: 'test',
      findings: [createFindingHelper({ severity: 'HIGH' })],
      summary: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 },
    } as any;

    const evaluation = evaluatePolicy(result, {
      policy: {
        rules: [
          { severity: 'HIGH', action: 'fail' },
          { severity: 'LOW', action: 'ignore' },
        ],
      },
    });

    expect(evaluation.passed).toBe(false);
    expect(evaluation.violations.length).toBe(1);
    expect(evaluation.violations[0].rule.severity).toBe('HIGH');
  });
});

describe('Security Profiles', () => {
  test('has all expected profiles', () => {
    const profiles = Object.keys(SECURITY_PROFILES);
    expect(profiles).toContain('webapp');
    expect(profiles).toContain('api');
    expect(profiles).toContain('ci');
    expect(profiles).toContain('enterprise');
  });

  test('gets profile by name', () => {
    const profile = getProfile('ENTERPRISE');
    expect(profile).not.toBeNull();
    expect(profile!.failOn).toBe('medium');
    expect(profile!.categories).toContain('cicd');
  });
});

describe('Plugin Architecture', () => {
  test('registers and retrieves plugins', () => {
    const registry = new PluginRegistry();
    const plugin = createPlugin({
      name: 'test-plugin',
      version: '1.0.0',
      description: 'Test plugin',
    });

    registry.register(plugin);
    expect(registry.getPlugin('test-plugin')).toBeDefined();
    expect(registry.getAllPlugins().length).toBe(1);
  });

  test('rejects duplicate plugin names', () => {
    const registry = new PluginRegistry();
    const plugin = createPlugin({
      name: 'dup',
      version: '1.0.0',
      description: 'dup',
    });

    registry.register(plugin);
    expect(() => registry.register(plugin)).toThrow();
  });

  test('runs hooks', async () => {
    const registry = new PluginRegistry();
    const plugin = createPlugin({
      name: 'hooks-plugin',
      version: '1.0.0',
      description: 'test hooks',
      hooks: {
        beforeScan: async () => { /* no-op */ },
        afterScan: async (findings) => findings,
      },
    });

    registry.register(plugin);
    expect(() => registry.runBeforeScanHooks({} as any)).not.toThrow();
  });
});

describe('MCP Integration', () => {
  test('creates MCP server with tools', () => {
    const server = createMCPServer();
    expect(server.name).toBe('lui-security');
    expect(server.tools.length).toBeGreaterThan(0);
    expect(server.tools[0].name).toBe('lui_scan');
  });
});

describe('Attack Surface Map', () => {
  test('builds attack surface from scan results', () => {
    const result = {
      target: 'test',
      findings: [
        createFindingHelper({
          id: 'LUI-API-001',
          category: 'API Security',
          title: 'Endpoint without authentication: POST /api/users',
        }),
        createFindingHelper({
          id: 'LUI-API-002',
          category: 'API Security',
          title: 'Endpoint without authentication: GET /login',
        }),
      ],
      technologyProfile: {
        databases: ['MySQL', 'PostgreSQL'],
        authMethods: ['OAuth'],
      },
    } as any;

    const surface = buildAttackSurface(result);
    expect(surface.public.endpoints.length).toBeGreaterThan(0);
    expect(surface.external.length).toBeGreaterThan(0);
  });
});

describe('Investigations', () => {
  test('finds environment file issues', () => {
    const indicators = investigateProject(FIXTURES_PATH);
    expect(indicators.length).toBeGreaterThan(0);
    expect(indicators.some(i => i.type === 'credential_exposure')).toBe(true);
  });
});

describe('Ask Lui', () => {
  test('explains low security score', () => {
    const result = {
      score: 62,
      summary: { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 0, INFO: 0 },
      findings: [
        createFindingHelper({ severity: 'HIGH', id: 'LUI-AUTHZ-001', title: 'Authorization issue' }),
        createFindingHelper({ severity: 'MEDIUM', category: 'Dependencies', title: 'Vulnerable dep' }),
      ],
    } as any;

    const response = askLui('Why is my security score low?', result);
    expect(response.answer).toContain('62');
    expect(response.answer).toContain('HIGH');
  });

  test('prioritizes fixes', () => {
    const result = {
      findings: [
        createFindingHelper({ severity: 'HIGH', id: 'LUI-001', title: 'SQLi' }),
        createFindingHelper({ severity: 'LOW', id: 'LUI-002', title: 'Minor' }),
      ],
    } as any;

    const response = askLui('What should I fix first?', result);
    expect(response.answer).toContain('LUI-001');
  });
});

describe('API Discovery Scanner', () => {
  test('discovers endpoints in source files', async () => {
    const scanner = new APIDiscoveryScanner();
    const context = {
      project: {
        rootPath: FIXTURES_PATH,
        sourceFiles: ['server.js'],
        technology: {},
        hasPackageJson: true,
        hasDockerfile: true,
        hasDockerCompose: true,
        hasCICD: false,
        hasGit: false,
        hasDotEnv: true,
        fileCount: 1,
        configFiles: [],
        infrastructureFiles: [],
        sensitiveFiles: [],
        totalSize: 0,
      },
      rootPath: FIXTURES_PATH,
      scanType: 'deep',
      config: { exclude: [] },
      fileContents: new Map(),
    } as any;

    const findings = await scanner.scan(context);
    expect(findings).toBeDefined();
  });
});