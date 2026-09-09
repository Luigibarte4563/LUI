import { ScanResult } from '../models/ScanResult';
import { Finding } from '../models/Finding';

export class JSONReporter {
  generate(result: ScanResult): string {
    const output = {
      tool: result.tool,
      version: result.version,
      target: result.target,
      scanType: result.scanType,
      scanDate: result.scanDate,
      duration: result.duration,
      score: result.score,
      scoreLabel: result.scoreLabel,
      summary: result.summary,
      technologyProfile: result.technologyProfile,
      attackSurfaces: result.attackSurfaces,
      findings: result.findings.map(f => this.formatFinding(f)),
    };
    return JSON.stringify(output, null, 2);
  }

  private formatFinding(finding: Finding): Record<string, unknown> {
    return {
      id: finding.id,
      title: finding.title,
      severity: finding.severity,
      confidence: finding.confidence,
      category: finding.category,
      type: finding.type,
      description: finding.description,
      impact: finding.impact,
      affectedFiles: finding.affectedFiles,
      evidence: finding.evidence,
      recommendation: finding.recommendation,
      remediation: finding.remediation,
      cwe: finding.cwe,
      cve: finding.cve,
      cvss: finding.cvss,
      status: finding.status,
      scanner: finding.scanner,
    };
  }
}
