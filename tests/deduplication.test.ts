import { deduplicateFindings, identifyAttackChains } from '../src/analysis/Deduplication';
import { Finding } from '../src/models/Finding';

function createTestFinding(overrides: Partial<Finding>): Finding {
  return {
    id: 'TEST-001',
    title: 'Test Finding',
    severity: 'MEDIUM',
    confidence: 'MEDIUM',
    category: 'Test',
    type: 'potential',
    description: 'Test',
    impact: 'Test',
    affectedFiles: [],
    evidence: [],
    recommendation: 'Test',
    references: [],
    status: 'open',
    scanner: 'Test',
    timestamp: Date.now(),
    ...overrides,
  };
}

describe('Deduplication', () => {
  test('removes duplicate findings', () => {
    const findings = [
      createTestFinding({ id: '1', title: 'SQL Injection', affectedFiles: [{ file: 'src/app.ts', line: 10 }] }),
      createTestFinding({ id: '2', title: 'SQL Injection', affectedFiles: [{ file: 'src/app.ts', line: 10 }] }),
    ];
    
    const deduplicated = deduplicateFindings(findings);
    expect(deduplicated.length).toBe(1);
  });

  test('keeps different findings', () => {
    const findings = [
      createTestFinding({ id: '1', title: 'SQL Injection', affectedFiles: [{ file: 'src/app.ts', line: 10 }] }),
      createTestFinding({ id: '2', title: 'XSS', affectedFiles: [{ file: 'src/app.ts', line: 20 }] }),
    ];
    
    const deduplicated = deduplicateFindings(findings);
    expect(deduplicated.length).toBe(2);
  });

  test('keeps higher confidence finding', () => {
    const findings = [
      createTestFinding({ id: '1', title: 'SQL Injection', confidence: 'LOW', affectedFiles: [{ file: 'src/app.ts', line: 10 }] }),
      createTestFinding({ id: '2', title: 'SQL Injection', confidence: 'HIGH', affectedFiles: [{ file: 'src/app.ts', line: 10 }] }),
    ];
    
    const deduplicated = deduplicateFindings(findings);
    expect(deduplicated.length).toBe(1);
    expect(deduplicated[0].confidence).toBe('HIGH');
  });
});

describe('Attack Chains', () => {
  test('identifies XSS + session chain', () => {
    const findings = [
      createTestFinding({ id: '1', title: 'Stored XSS', category: 'XSS' }),
      createTestFinding({ id: '2', title: 'Token in localStorage', category: 'Authentication' }),
    ];
    
    const chains = identifyAttackChains(findings);
    expect(chains.length).toBeGreaterThan(0);
    expect(chains[0].title).toContain('XSS');
  });

  test('identifies SQL injection + authorization chain', () => {
    const findings = [
      createTestFinding({ id: '1', title: 'SQL Injection', category: 'Injection' }),
      createTestFinding({ id: '2', title: 'Missing authorization', category: 'Authorization' }),
    ];
    
    const chains = identifyAttackChains(findings);
    expect(chains.length).toBeGreaterThan(0);
  });

  test('returns empty for no relevant findings', () => {
    const findings = [
      createTestFinding({ id: '1', title: 'Low risk issue', category: 'Configuration' }),
    ];
    
    const chains = identifyAttackChains(findings);
    expect(chains.length).toBe(0);
  });
});
