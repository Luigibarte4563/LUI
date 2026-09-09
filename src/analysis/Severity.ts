import { Finding, Severity } from '../models/Finding';

export function calculateScore(findings: Finding[]): { score: number; label: string } {
  if (findings.length === 0) return { score: 100, label: 'Strong' };

  let deductions = 0;
  for (const finding of findings) {
    if (finding.status === 'suppressed') continue;
    switch (finding.severity) {
      case 'CRITICAL': deductions += 15; break;
      case 'HIGH': deductions += 8; break;
      case 'MEDIUM': deductions += 4; break;
      case 'LOW': deductions += 1; break;
      case 'INFO': deductions += 0.5; break;
    }
    // Reduce deduction for low confidence
    if (finding.confidence === 'LOW') deductions *= 0.5;
    if (finding.confidence === 'MEDIUM') deductions *= 0.8;
  }

  const score = Math.max(0, Math.min(100, Math.round(100 - deductions)));
  const label = getScoreLabel(score);
  return { score, label };
}

function getScoreLabel(score: number): string {
  if (score >= 85) return 'Strong';
  if (score >= 70) return 'Good';
  if (score >= 50) return 'Needs Improvement';
  if (score >= 30) return 'Poor';
  return 'Critical';
}

export function getSeveritySummary(findings: Finding[]): Record<Severity, number> {
  const summary: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const finding of findings) {
    if (finding.status !== 'suppressed') {
      summary[finding.severity]++;
    }
  }
  return summary;
}

export function getTopFindings(findings: Finding[], limit: number = 5): Finding[] {
  const severityOrder: Record<Severity, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  return findings
    .filter(f => f.status !== 'suppressed')
    .sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity])
    .slice(0, limit);
}
