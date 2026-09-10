import { Finding, FileLocation } from '../models/Finding';
import { DataFlow } from './DataFlow';

export interface EvidenceExplanation {
  findingId: string;
  dataFlowSteps: FlowStep[];
  sanitizationStatus: 'NOT_DETECTED' | 'PARTIAL' | 'EFFECTIVE';
  confidenceReason: string;
  codeContext: CodeContext;
}

export interface FlowStep {
  label: string;
  detail: string;
  line?: number;
  file?: string;
  type: 'source' | 'transform' | 'sink' | 'sanitization' | 'output';
}

export interface CodeContext {
  vulnerableLine: string;
  surroundingLines: string[];
  startLine: number;
  endLine: number;
}

const SANITIZE_PATTERNS: RegExp[] = [
  /(?:sanitize|escape|encode|clean|validate|whitelist|allowlist|parameterize|prepared|preparedStatement|placeholder|\?)/i,
  /(?:htmlentities|htmlspecialchars|DOMPurify|purify|xss|csrf|helmet|validator)/i,
  /(?:parseInt|parseFloat|Number|parseInt\(|parseFloat\()/,
  /(?:\.replace\([^)]*(?:script|html|<|>|&|quot))/i,
];

export function buildEvidenceExplanation(
  finding: Finding,
  dataFlows: DataFlow[],
  getContent: (file: string) => string | null
): EvidenceExplanation {
  const steps = buildFlowSteps(finding, dataFlows, getContent);
  const sanitization = detectSanitization(finding, getContent);
  const codeCtx = extractCodeContext(finding, getContent);
  const confidenceReason = explainConfidence(finding, steps, sanitization);

  return {
    findingId: finding.id,
    dataFlowSteps: steps,
    sanitizationStatus: sanitization,
    confidenceReason,
    codeContext: codeCtx,
  };
}

function buildFlowSteps(
  finding: Finding,
  dataFlows: DataFlow[],
  getContent: (file: string) => string | null
): FlowStep[] {
  const steps: FlowStep[] = [];
  const location = finding.affectedFiles[0];
  if (!location) return steps;

  const matchingFlow = dataFlows.find(f =>
    f.file === location.file && Math.abs(f.sinkLine - (location.line || 0)) <= 5
  );

  if (matchingFlow) {
    steps.push({
      label: 'User Input',
      detail: `External input enters the application via ${matchingFlow.source}`,
      type: 'source',
    });

    if (matchingFlow.variables.length > 0) {
      for (const v of matchingFlow.variables) {
        steps.push({
          label: `Variable: ${v}`,
          detail: `Input is assigned to variable "${v}"`,
          type: 'transform',
        });
      }
    }

    steps.push({
      label: 'Data transformation',
      detail: 'Input flows through application logic without sanitization',
      type: 'transform',
    });

    steps.push({
      label: matchingFlow.sink,
      detail: `Tainted data reaches unsafe ${matchingFlow.sink} at line ${matchingFlow.sinkLine}`,
      file: matchingFlow.file,
      line: matchingFlow.sinkLine,
      type: 'sink',
    });
  } else {
    steps.push({
      label: 'User Input',
      detail: 'External input enters the application',
      type: 'source',
    });

    steps.push({
      label: 'Unsafe operation',
      detail: finding.description,
      file: location.file,
      line: location.line,
      type: 'sink',
    });
  }

  return steps;
}

function detectSanitization(
  finding: Finding,
  getContent: (file: string) => string | null
): 'NOT_DETECTED' | 'PARTIAL' | 'EFFECTIVE' {
  const location = finding.affectedFiles[0];
  if (!location) return 'NOT_DETECTED';

  const content = getContent(location.file);
  if (!content) return 'NOT_DETECTED';

  const lines = content.split('\n');
  const sinkLine = (location.line || 1) - 1;
  const windowStart = Math.max(0, sinkLine - 30);
  const windowEnd = Math.min(lines.length, sinkLine + 5);
  const window = lines.slice(windowStart, windowEnd).join('\n');

  const foundSanitizers: RegExp[] = [];
  for (const pattern of SANITIZE_PATTERNS) {
    if (pattern.test(window)) {
      foundSanitizers.push(pattern);
    }
  }

  if (foundSanitizers.length >= 2) return 'EFFECTIVE';
  if (foundSanitizers.length === 1) return 'PARTIAL';
  return 'NOT_DETECTED';
}

function extractCodeContext(
  finding: Finding,
  getContent: (file: string) => string | null
): CodeContext {
  const location = finding.affectedFiles[0];
  const empty: CodeContext = { vulnerableLine: '', surroundingLines: [], startLine: 0, endLine: 0 };

  if (!location) return empty;

  const content = getContent(location.file);
  if (!content) return empty;

  const lines = content.split('\n');
  const targetLine = (location.line || 1) - 1;
  const start = Math.max(0, targetLine - 5);
  const end = Math.min(lines.length, targetLine + 6);

  return {
    vulnerableLine: lines[targetLine] || '',
    surroundingLines: lines.slice(start, end),
    startLine: start + 1,
    endLine: end,
  };
}

function explainConfidence(
  finding: Finding,
  steps: FlowStep[],
  sanitization: 'NOT_DETECTED' | 'PARTIAL' | 'EFFECTIVE'
): string {
  const reasons: string[] = [];

  if (finding.type === 'confirmed') {
    reasons.push('Data flow analysis confirmed a source-to-sink path');
  } else if (steps.length > 2) {
    reasons.push('Multi-step data flow identified');
  } else {
    reasons.push('Pattern-based detection');
  }

  if (sanitization === 'NOT_DETECTED') {
    reasons.push('No sanitization or encoding detected in the code path');
  } else if (sanitization === 'PARTIAL') {
    reasons.push('Some sanitization present but may be insufficient');
  } else {
    reasons.push('Sanitization detected; verify it is applied correctly');
  }

  if (finding.confidence === 'HIGH') {
    reasons.push('High confidence: direct user input to dangerous sink');
  } else if (finding.confidence === 'LOW') {
    reasons.push('Low confidence: indirect or heuristic match');
  }

  return reasons.join('. ') + '.';
}

export function formatEvidenceReport(explanation: EvidenceExplanation): string {
  const lines: string[] = [];
  const { dataFlowSteps, sanitizationStatus, confidenceReason, codeContext } = explanation;

  lines.push('DATA FLOW');
  lines.push('');
  for (const step of dataFlowSteps) {
    lines.push(`  ${step.label}`);
    lines.push(`    ${step.detail}`);
    if (step.file && step.line) {
      lines.push(`    ${step.file}:${step.line}`);
    }
    lines.push('        ↓');
  }
  lines.pop();

  lines.push('');
  lines.push(`Sanitization: ${sanitizationStatus}`);
  lines.push('');
  lines.push(`Confidence: ${explanation.findingId}`);
  lines.push(confidenceReason);

  return lines.join('\n');
}
