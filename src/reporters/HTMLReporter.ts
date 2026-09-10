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
    const riskAreas = this.buildRiskAreas(result);
    const contextGraph = result.contextGraph;
    const riskPriorities = result.riskPriorities || [];
    const endpoints = result.endpoints || [];
    const depGraph = result.dependencyGraph;

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Lui Security Dashboard</title>
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
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 1rem; margin: 2rem 0; }
    .stat-card { background: #1e293b; padding: 1.5rem; border-radius: 8px; text-align: center; transition: transform 0.2s; }
    .stat-card:hover { transform: translateY(-2px); }
    .stat-value { font-size: 2rem; font-weight: 700; }
    .stat-label { color: #94a3b8; font-size: 0.9rem; margin-top: 0.25rem; }
    .section { margin: 2rem 0; }
    .section h2 { font-size: 1.5rem; margin-bottom: 1rem; color: #f1f5f9; border-bottom: 1px solid #334155; padding-bottom: 0.5rem; }
    .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; }
    @media (max-width: 768px) { .two-col { grid-template-columns: 1fr; } }
    .finding { background: #1e293b; border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem; border-left: 4px solid; transition: background 0.2s; }
    .finding:hover { background: #2a3a52; }
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
    .risk-bar { display: flex; align-items: center; margin: 0.5rem 0; }
    .risk-label { width: 140px; font-size: 0.9rem; color: #94a3b8; }
    .risk-track { flex: 1; background: #1e293b; border-radius: 4px; height: 16px; overflow: hidden; }
    .risk-fill { height: 100%; border-radius: 4px; }
    .risk-count { width: 40px; text-align: right; font-weight: 600; }
    .priority-pill { padding: 0.25rem 0.6rem; border-radius: 4px; font-size: 0.8rem; font-weight: 700; }
    .flow-arrow { color: #38bdf8; font-size: 1.2rem; }
    .footer { text-align: center; padding: 2rem 0; color: #64748b; font-size: 0.85rem; border-top: 1px solid #1e293b; margin-top: 3rem; }
    .matrix-ok { color: #22c55e; }
    .matrix-warn { color: #f59e0b; }
    .matrix-fail { color: #ef4444; }
    .graph-node { display: inline-block; background: #334155; padding: 0.3rem 0.8rem; border-radius: 16px; font-size: 0.85rem; margin: 0.25rem; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Lui Security Dashboard</h1>
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
      <div class="stat-card">
        <div class="stat-value">${contextGraph ? contextGraph.nodes.length : 0}</div>
        <div class="stat-label">Graph Nodes</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${contextGraph ? contextGraph.chainCount : 0}</div>
        <div class="stat-label">Data Flow Chains</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${endpoints.length}</div>
        <div class="stat-label">API Endpoints</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${depGraph ? depGraph.vulnerableCount : 0}</div>
        <div class="stat-label">Vulnerable Dependencies</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${riskPriorities.filter(r => r.priority === 'P0').length}</div>
        <div class="stat-label">P0 Priorities</div>
      </div>
    </div>

    <div class="section">
      <h2>Technology</h2>
      <div>${techStr.split(' + ').map(t => `<span class="tech-tag">${t}</span>`).join('')}</div>
    </div>

    <div class="two-col">
      <div class="section">
        <h2>Top Risk Areas</h2>
        ${this.renderRiskAreas(riskAreas)}
      </div>

      <div class="section">
        <h2>Risk Priorities</h2>
        ${this.renderRiskPriorities(riskPriorities.slice(0, 8), result)}
      </div>
    </div>

    ${endpoints.length > 0 ? `<div class="section">
      <h2>Endpoint Security Matrix</h2>
      ${this.renderEndpointMatrix(endpoints)}
    </div>` : ''}

    ${depGraph && depGraph.vulnerablePaths.length > 0 ? `<div class="section">
      <h2>Vulnerable Dependencies</h2>
      ${this.renderVulnerableDeps(depGraph.vulnerablePaths)}
    </div>` : ''}

    ${contextGraph && contextGraph.nodes.length > 0 ? `<div class="section">
      <h2>Security Context Graph</h2>
      <p style="color: #94a3b8; margin-bottom: 1rem;">${contextGraph.nodes.length} nodes, ${contextGraph.edges.length} edges, ${contextGraph.chainCount} data flow chains identified.</p>
      <div>${contextGraph.nodes.slice(0, 40).map(n => `<span class="graph-node">${n.label}</span>`).join('')}</div>
    </div>` : ''}

    <div class="section">
      <h2>Findings</h2>
      ${this.renderFindings(result.findings.filter(f => f.status !== 'suppressed'))}
    </div>

    <div class="footer">
      Lui Security Auditor | Generated ${new Date(result.scanDate).toLocaleString()}
    </div>
  </div>
</body>
</html>`;
  }

  private renderRiskAreas(areas: Array<{ label: string; count: number; color: string }>): string {
    if (areas.length === 0) return '<p>No risk areas identified.</p>';
    const max = Math.max(...areas.map(a => a.count), 1);

    return areas.map(area => `
      <div class="risk-bar">
        <div class="risk-label">${area.label}</div>
        <div class="risk-track">
          <div class="risk-fill" style="width: ${(area.count / max) * 100}%; background: ${area.color};"></div>
        </div>
        <div class="risk-count">${area.count}</div>
      </div>`).join('');
  }

  private renderRiskPriorities(priorities: Array<{ findingId: string; priority: string; score: number; reasoning: string }>, result: ScanResult): string {
    if (priorities.length === 0) return '<p>No priorities computed.</p>';

    return `<table>
      <thead><tr><th>Finding</th><th>Priority</th><th>Score</th><th>Title</th></tr></thead>
      <tbody>
        ${priorities.map(p => {
          const finding = result.findings.find(f => f.id === p.findingId);
          return `<tr>
            <td class="file-ref">${p.findingId}</td>
            <td><span class="priority-pill" style="background: ${this.getPriorityColor(p.priority)}; color: white;">${p.priority}</span></td>
            <td>${p.score}</td>
            <td>${finding ? finding.title : p.reasoning}</td>
          </tr>`;
        }).join('')}
      </tbody>
    </table>`;
  }

  private renderEndpointMatrix(endpoints: Array<{ method: string; path: string; hasAuth: boolean; hasAuthz: boolean; hasValidation: boolean }>): string {
    return `<table>
      <thead><tr><th>Endpoint</th><th>Auth</th><th>AuthZ</th><th>Validation</th></tr></thead>
      <tbody>
        ${endpoints.slice(0, 30).map(ep => `<tr>
          <td class="file-ref">${ep.method} ${ep.path}</td>
          <td class="${ep.hasAuth ? 'matrix-ok' : 'matrix-fail'}">${ep.hasAuth ? '✓' : '✗'}</td>
          <td class="${ep.hasAuthz ? 'matrix-ok' : ep.hasAuth ? 'matrix-warn' : 'matrix-warn'}">${ep.hasAuthz ? '✓' : ep.hasAuth ? '⚠' : 'N/A'}</td>
          <td class="${ep.hasValidation ? 'matrix-ok' : 'matrix-warn'}">${ep.hasValidation ? '✓' : '⚠'}</td>
        </tr>`).join('')}
      </tbody>
    </table>`;
  }

  private renderVulnerableDeps(paths: Array<{ path: string[]; findingId: string; severity: string }>): string {
    return `<table>
      <thead><tr><th>Path</th><th>Finding</th><th>Severity</th></tr></thead>
      <tbody>
        ${paths.map(vp => `<tr>
          <td class="file-ref">${vp.path.join(' → ')}</td>
          <td>${vp.findingId}</td>
          <td style="color: ${SEVERITY_COLORS[vp.severity as Severity] || '#e2e8f0'}">${vp.severity}</td>
        </tr>`).join('')}
      </tbody>
    </table>`;
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
        <div class="finding" style="border-left-color: ${SEVERITY_COLORS[finding.severity]};">
          <div class="finding-header">
            <div>
              <span class="finding-id" style="color: #64748b;">${finding.id}</span>
              <span class="finding-title">${finding.title}</span>
            </div>
            <div>
              ${finding.riskPriority ? `<span class="priority-pill" style="background: ${this.getPriorityColor(finding.riskPriority)}; color: white; margin-right: 0.5rem;">${finding.riskPriority}</span>` : ''}
              <span class="badge" style="background: ${SEVERITY_COLORS[finding.severity]}; color: white;">${finding.severity}</span>
            </div>
          </div>
          <div class="finding-body">
            <dl>
              <dt>Confidence</dt>
              <dd>${finding.confidence} ${finding.type === 'confirmed' ? '· Data flow confirmed' : ''}</dd>
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
              ${finding.dataFlowSteps && finding.dataFlowSteps.length > 0 ? `<dt>Data Flow</dt><dd>${finding.dataFlowSteps.map(s => s.label).join('<span class="flow-arrow"> ↓ </span>')}</dd>` : ''}
              ${finding.aiAnalysis?.enrichedDescription ? `<dt>AI Analysis</dt><dd><span class="ai-badge">✦ LLM-verified</span><br/>${finding.aiAnalysis.enrichedDescription}${finding.aiAnalysis.exploitScenario ? '<br/><br/><strong>Exploitation scenario:</strong><br/>' + finding.aiAnalysis.exploitScenario : ''}</dd>` : ''}
            </dl>
          </div>
        </div>`;
      }
    }

    return html;
  }

  private buildRiskAreas(result: ScanResult): Array<{ label: string; count: number; color: string }> {
    const categories = new Map<string, number>();
    for (const finding of result.findings) {
      if (finding.status === 'suppressed') continue;
      const key = finding.category;
      categories.set(key, (categories.get(key) || 0) + 1);
    }

    const sevByCat = new Map<string, string>();
    for (const finding of result.findings) {
      if (finding.status === 'suppressed') continue;
      const current = sevByCat.get(finding.category);
      if (!current || this.severityRank(finding.severity) < this.severityRank(current as Severity)) {
        sevByCat.set(finding.category, finding.severity);
      }
    }

    return Array.from(categories.entries())
      .sort((a, b) => b[1] - a[1])
      .map(([label, count]) => ({
        label,
        count,
        color: SEVERITY_COLORS[sevByCat.get(label) as Severity] || '#6b7280',
      }));
  }

  private severityRank(sev: Severity): number {
    const order: Record<Severity, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
    return order[sev];
  }

  private getPriorityColor(priority: string): string {
    switch (priority) {
      case 'P0': return '#dc2626';
      case 'P1': return '#ef4444';
      case 'P2': return '#f59e0b';
      default: return '#3b82f6';
    }
  }

  private getScoreColor(score: number): string {
    if (score >= 85) return '#22c55e';
    if (score >= 70) return '#22c55e';
    if (score >= 50) return '#f59e0b';
    if (score >= 30) return '#ef4444';
    return '#dc2626';
  }
}