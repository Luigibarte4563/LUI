export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type Confidence = 'HIGH' | 'MEDIUM' | 'LOW';
export type FindingStatus = 'open' | 'suppressed' | 'fixed';
export type FindingType = 'confirmed' | 'potential' | 'heuristic';

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  category: string;
  type: FindingType;
  description: string;
  impact: string;
  affectedFiles: FileLocation[];
  evidence: string[];
  recommendation: string;
  remediation?: string;
  codeExample?: string;
  references: string[];
  cwe?: string;
  cve?: string;
  cvss?: number;
  status: FindingStatus;
  scanner: string;
  timestamp: number;
}

export interface FileLocation {
  file: string;
  line?: number;
  column?: number;
  snippet?: string;
}

export function createFinding(overrides: Partial<Finding> & Pick<Finding, 'id' | 'title' | 'severity' | 'category' | 'description'>): Finding {
  return {
    confidence: 'MEDIUM',
    type: 'potential',
    impact: '',
    affectedFiles: [],
    evidence: [],
    recommendation: '',
    references: [],
    status: 'open',
    scanner: '',
    timestamp: Date.now(),
    ...overrides,
  };
}

const SEVERITY_WEIGHT: Record<Severity, number> = {
  CRITICAL: 10,
  HIGH: 7,
  MEDIUM: 4,
  LOW: 2,
  INFO: 1,
};

export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY_WEIGHT[b] - SEVERITY_WEIGHT[a];
}

export function severityLabel(severity: Severity): string {
  return severity.padEnd(8);
}
