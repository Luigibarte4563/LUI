import { Finding, Severity, LifecycleStatus } from './Finding';

export interface ScanResult {
  tool: string;
  version: string;
  target: string;
  scanType: 'quick' | 'standard' | 'deep';
  score: number;
  scoreLabel: string;
  summary: Record<Severity, number>;
  findings: Finding[];
  scanDate: string;
  duration: number;
  technologyProfile: TechnologyProfile;
  attackSurfaces: string[];
  attackChains: Array<{ id: string; title: string; description: string; confidence: string; impact: string; steps: Finding[] }>;
  metadata: Record<string, unknown>;
  contextGraph?: ContextGraphData;
  riskPriorities?: RiskPriorityData[];
  endpoints?: EndpointData[];
  dependencyGraph?: DependencyGraphData;
}

export interface ContextGraphData {
  nodes: Array<{ id: string; type: string; label: string }>;
  edges: Array<{ from: string; to: string; label: string; type: string }>;
  chainCount: number;
}

export interface RiskPriorityData {
  findingId: string;
  priority: string;
  score: number;
  reasoning: string;
}

export interface EndpointData {
  method: string;
  path: string;
  file: string;
  hasAuth: boolean;
  hasAuthz: boolean;
  hasValidation: boolean;
}

export interface DependencyGraphData {
  rootCount: number;
  vulnerableCount: number;
  vulnerablePaths: Array<{ path: string[]; findingId: string; severity: string }>;
}

export interface TechnologyProfile {
  languages: string[];
  frameworks: string[];
  databases: string[];
  authMethods: string[];
  deployment: string[];
  frontend: string[];
  backend: string[];
  infrastructure: string[];
  packageManagers: string[];
  raw: Record<string, string>;
}

export function createScanResult(overrides: Partial<ScanResult> & Pick<ScanResult, 'target'>): ScanResult {
  return {
    tool: 'Lui',
    version: '0.1.0',
    scanType: 'standard',
    score: 0,
    scoreLabel: '',
    summary: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
    findings: [],
    scanDate: new Date().toISOString(),
    duration: 0,
    technologyProfile: {
      languages: [],
      frameworks: [],
      databases: [],
      authMethods: [],
      deployment: [],
      frontend: [],
      backend: [],
      infrastructure: [],
      packageManagers: [],
      raw: {},
    },
    attackSurfaces: [],
    attackChains: [],
    metadata: {},
    ...overrides,
  };
}
