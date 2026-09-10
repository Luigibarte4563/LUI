import { Finding } from '../models/Finding';
import { DataFlow } from './DataFlow';

export interface RiskPriority {
  findingId: string;
  priority: 'P0' | 'P1' | 'P2' | 'P3';
  score: number;
  factors: RiskFactors;
  reasoning: string;
}

export interface RiskFactors {
  severity: number;
  confidence: number;
  exposure: number;
  reachability: number;
  exploitability: number;
}

const SEVERITY_SCORE: Record<string, number> = {
  CRITICAL: 10,
  HIGH: 7,
  MEDIUM: 4,
  LOW: 2,
  INFO: 0.5,
};

const CONFIDENCE_SCORE: Record<string, number> = {
  HIGH: 1.0,
  MEDIUM: 0.7,
  LOW: 0.3,
};

const CATEGORY_EXPOSURE: Record<string, number> = {
  'Secrets': 0.9,
  'Injection': 0.95,
  'XSS': 0.8,
  'Authentication': 0.85,
  'Authorization': 0.9,
  'Dependencies': 0.7,
  'Docker Security': 0.6,
  'CI/CD': 0.5,
  'Configuration': 0.65,
  'API Security': 0.75,
};

export function prioritizeFindings(
  findings: Finding[],
  dataFlows: DataFlow[]
): RiskPriority[] {
  const priorities: RiskPriority[] = [];

  for (const finding of findings) {
    if (finding.status === 'suppressed') continue;

    const severity = SEVERITY_SCORE[finding.severity] || 0;
    const confidence = CONFIDENCE_SCORE[finding.confidence] || 0.5;
    const exposure = CATEGORY_EXPOSURE[finding.category] || 0.5;
    const reachability = calculateReachability(finding, dataFlows);
    const exploitability = calculateExploitability(finding);

    const combined = confidence * 0.25 + exposure * 0.25 + reachability * 0.25 + exploitability * 0.25;
    const score = Math.round(Math.min(100, (severity / 10) * combined * 100));

    const priority = scoreToPriority(score);
    const reasoning = buildReasoning(finding, { severity, confidence, exposure, reachability, exploitability });

    priorities.push({
      findingId: finding.id,
      priority,
      score,
      factors: { severity, confidence, exposure, reachability, exploitability },
      reasoning,
    });
  }

  priorities.sort((a, b) => b.score - a.score);
  return priorities;
}

function calculateReachability(finding: Finding, dataFlows: DataFlow[]): number {
  const location = finding.affectedFiles[0];
  if (!location || typeof location.line !== 'number') return 0.5;

  const flow = dataFlows.find(f =>
    f.file === location.file && Math.abs(f.sinkLine - (location.line || 0)) <= 5
  );

  if (!flow) return 0.3;
  if (flow.confidence === 'HIGH') return 0.9;
  return 0.6;
}

function calculateExploitability(finding: Finding): number {
  const category = finding.category;
  const type = finding.type;

  let base = 0.5;

  if (category === 'Injection' || category === 'XSS') base = 0.9;
  else if (category === 'Secrets') base = 0.8;
  else if (category === 'Authentication' || category === 'Authorization') base = 0.7;
  else if (category === 'Dependencies') base = 0.6;
  else if (category === 'Docker Security') base = 0.4;
  else if (category === 'CI/CD') base = 0.3;

  if (type === 'confirmed') base = Math.min(1.0, base + 0.2);

  return base;
}

function scoreToPriority(score: number): 'P0' | 'P1' | 'P2' | 'P3' {
  if (score >= 80) return 'P0';
  if (score >= 60) return 'P1';
  if (score >= 40) return 'P2';
  return 'P3';
}

function buildReasoning(finding: Finding, factors: RiskFactors): string {
  const parts: string[] = [];

  if (factors.severity >= 7) {
    parts.push(`High severity (${finding.severity})`);
  } else if (factors.severity <= 2) {
    parts.push(`Low severity (${finding.severity})`);
  }

  if (factors.confidence >= 0.8) {
    parts.push('confirmed via data flow analysis');
  } else if (factors.confidence <= 0.3) {
    parts.push('low confidence heuristic match');
  }

  if (factors.reachability >= 0.8) {
    parts.push('directly reachable from user input');
  } else if (factors.reachability <= 0.3) {
    parts.push('limited reachability');
  }

  if (factors.exploitability >= 0.8) {
    parts.push('highly exploitable');
  }

  return parts.length > 0 ? parts.join(', ') + '.' : 'Standard risk profile.';
}
