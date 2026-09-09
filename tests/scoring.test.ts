import { calculateScore, getSeveritySummary } from '../src/analysis/Severity';
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

describe('Scoring', () => {
  test('returns 100 for no findings', () => {
    const result = calculateScore([]);
    expect(result.score).toBe(100);
    expect(result.label).toBe('Strong');
  });

  test('reduces score for critical findings', () => {
    const findings = [createTestFinding({ severity: 'CRITICAL' })];
    const result = calculateScore(findings);
    expect(result.score).toBeLessThan(100);
  });

  test('reduces score more for multiple critical findings', () => {
    const findings = [
      createTestFinding({ id: '1', severity: 'CRITICAL' }),
      createTestFinding({ id: '2', severity: 'CRITICAL' }),
      createTestFinding({ id: '3', severity: 'CRITICAL' }),
    ];
    const result = calculateScore(findings);
    expect(result.score).toBeLessThan(80);
  });

  test('ignores suppressed findings', () => {
    const findings = [createTestFinding({ severity: 'CRITICAL', status: 'suppressed' })];
    const result = calculateScore(findings);
    expect(result.score).toBe(100);
  });

  test('gives appropriate labels', () => {
    expect(calculateScore([]).label).toBe('Strong');
    
    const criticalFindings = Array(10).fill(null).map((_, i) => 
      createTestFinding({ id: `crit-${i}`, severity: 'CRITICAL' })
    );
    const result = calculateScore(criticalFindings);
    expect(result.score).toBeLessThan(50);
  });
});

describe('Severity Summary', () => {
  test('counts findings by severity', () => {
    const findings = [
      createTestFinding({ id: '1', severity: 'CRITICAL' }),
      createTestFinding({ id: '2', severity: 'HIGH' }),
      createTestFinding({ id: '3', severity: 'HIGH' }),
      createTestFinding({ id: '4', severity: 'MEDIUM' }),
      createTestFinding({ id: '5', severity: 'LOW' }),
      createTestFinding({ id: '6', severity: 'INFO' }),
    ];
    
    const summary = getSeveritySummary(findings);
    expect(summary.CRITICAL).toBe(1);
    expect(summary.HIGH).toBe(2);
    expect(summary.MEDIUM).toBe(1);
    expect(summary.LOW).toBe(1);
    expect(summary.INFO).toBe(1);
  });

  test('ignores suppressed findings', () => {
    const findings = [
      createTestFinding({ id: '1', severity: 'CRITICAL', status: 'suppressed' }),
      createTestFinding({ id: '2', severity: 'HIGH' }),
    ];
    
    const summary = getSeveritySummary(findings);
    expect(summary.CRITICAL).toBe(0);
    expect(summary.HIGH).toBe(1);
  });
});
