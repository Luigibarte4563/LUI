import { ScanResult } from '../models/ScanResult';
import { Finding, Severity } from '../models/Finding';

const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: '#dc2626',
  HIGH: '#ef4444',
  MEDIUM: '#f59e0b',
  LOW: '#3b82f6',
  INFO: '#6b7280',
};

const SEVERITY_BG: Record<Severity, string> = {
  CRITICAL: '#fef2f2',
  HIGH: '#fef2f2',
  MEDIUM: '#fffbeb',
  LOW: '#eff6ff',
  INFO: '#f9fafb',
};

export class HTMLReporter {
  generate(result: ScanResult): string {
    const tech = result.technologyProfile;
    const techStr = [...tech.languages, ...tech.frameworks].join(' + ') || 'Unknown';
    
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Lui Security Report</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; }
    .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
    .header { text-align: center; padding: 3rem 0; border-bottom: 1px solid #1e293b; margin-bottom: 2rem; }
    .header h1 { font-size: 2.5rem; color: #38bdf8; margin-bottom: 0.5rem; font-weight: 700; }
    .header p { color: #94a3b8; font-size: 1.1rem; }
    .score-section { text-align: center; padding: 2rem; background: #1e293b; border-radius: 12px; margin-bottom: 2rem; }
    .score { font-size: 4rem; font-weight: 700; }
    .score-label { font-size: 1.2rem; color: #94a3b8; margin-top: 0.5rem; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin: 2rem 0; }
    .stat-card { background: #1e293b; padding: 1.5rem; border-radius: 8px; text-align: center; }
    .stat-value { font-size: 2rem; font-weight: 700; }
    .stat-label { color: #94a3b8; font-size: 0.9rem; margin-top: 0.25rem; }
    .section { margin: 2rem 0; }
    .section h2 { font-size: 1.5rem; margin-bottom: 1rem; color: #f1f5f9; border-bottom: 1px solid #334155; padding-bottom: 0.5rem; }
    .finding { background: #1e293b; border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem; border-left: 4px solid; }
    .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
    .finding-id { font-family: monospace; color: #94a3b8; }
    .finding-title { font-size: 1.1rem; font-weight: 600; }
    .badge { padding: 0.25rem 0.75rem; border-radius: 4px; font-size: 0.8rem; font-weight: 600; text-transform: uppercase; }
    .finding-body { font-size: 0.95rem; }
    .finding-body dt { color: #94a3b8; font-size: 0.85rem; margin-top: 0.75rem; }
    .finding-body dd { margin-left: 0; }
    .file-ref { font-family: monospace; background: #0f172a; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.85rem; }
    .tech-tag { display: inline-block; background: #334155; padding: 0.25rem 0.75rem; border-radius: 4px; font-size: 0.85rem; margin: 0.25rem; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid #334155; }
    th { color: #94a3b8; font-weight: 500; }
    .footer { text-align: center; padding: 2rem 0; color: #64748b; font-size: 0.85rem; border-top: 1px solid #1e293b; margin-top: 3rem; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Lui Security Report</h1>
      <p>${result.target} | ${result.scanType} scan | ${new Date(result.scanDate).toLocaleDateString()}</p>
    </div>

    <div class="score-section">
      <div class="score" style="color: ${this.getScoreColor(result.score)}">${result.score}/100</div>
      <div class="score-label">${result.scoreLabel}</div>
    </div>

    <div class="grid">
      <div class="stat-card">
        <div class="stat-value" style="color: ${SEVERITY_COLORS.CRITICAL}">${result.summary.CRITICAL}</div>
        <div class="stat-label">Critical</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" style="color: ${SEVERITY_COLORS.HIGH}">${result.summary.HIGH}</div>
        <div class="stat-label">High</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" style="color: ${SEVERITY_COLORS.MEDIUM}">${result.summary.MEDIUM}</div>
        <div class="stat-label">Medium</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" style="color: ${SEVERITY_COLORS.LOW}">${result.summary.LOW}</div>
        <div class="stat-label">Low</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" style="color: ${SEVERITY_COLORS.INFO}">${result.summary.INFO}</div>
        <div class="stat-label">Info</div>
      </div>
    </div>

    <div class="section">
      <h2>Technology</h2>
      <div>${techStr.split(' + ').map(t => `<span class="tech-tag">${t}</span>`).join('')}</div>
    </div>

    <div class="section">
      <h2>Findings</h2>
      ${this.renderFindings(result.findings.filter(f => f.status !== 'suppressed'))}
    </div>

    <div class="footer">
      Lui Security Auditor v0.1.0 | Generated ${new Date(result.scanDate).toLocaleString()}
    </div>
  </div>
</body>
</html>`;
  }

  private renderFindings(findings: Finding[]): string {
    if (findings.length === 0) {
      return '<p style="color: #22c55e; font-size: 1.2rem;">No security issues found.</p>';
    }

    const severities: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    let html = '';

    for (const severity of severities) {
      const sevFindings = findings.filter(f => f.severity === severity);
      if (sevFindings.length === 0) continue;

      html += `<h3 style="color: ${SEVERITY_COLORS[severity]}; margin: 1.5rem 0 1rem;">${severity} (${sevFindings.length})</h3>`;

      for (const finding of sevFindings) {
        html += `
        <div class="finding" style="border-left-color: ${SEVERITY_COLORS[finding.severity]}; background: ${SEVERITY_BG[finding.severity]}; color: #1e293b;">
          <div class="finding-header">
            <div>
              <span class="finding-id" style="color: #64748b;">${finding.id}</span>
              <span class="finding-title">${finding.title}</span>
            </div>
            <span class="badge" style="background: ${SEVERITY_COLORS[finding.severity]}; color: white;">${finding.severity}</span>
          </div>
          <div class="finding-body">
            <dl>
              <dt>Confidence</dt>
              <dd>${finding.confidence}</dd>
              <dt>Category</dt>
              <dd>${finding.category}</dd>
              ${finding.cwe ? `<dt>CWE</dt><dd>${finding.cwe}</dd>` : ''}
              ${finding.affectedFiles.length > 0 ? `<dt>Location</dt><dd>${finding.affectedFiles.map(f => `<span class="file-ref">${f.file}${f.line ? ':' + f.line : ''}</span>`).join(', ')}</dd>` : ''}
              <dt>Description</dt>
              <dd>${finding.description}</dd>
              <dt>Impact</dt>
              <dd>${finding.impact}</dd>
              <dt>Recommendation</dt>
              <dd>${finding.recommendation}</dd>
            </dl>
          </div>
        </div>`;
      }
    }

    return html;
  }

  private getScoreColor(score: number): string {
    if (score >= 85) return '#22c55e';
    if (score >= 70) return '#22c55e';
    if (score >= 50) return '#f59e0b';
    if (score >= 30) return '#ef4444';
    return '#dc2626';
  }
}
