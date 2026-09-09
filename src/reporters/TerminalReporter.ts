import chalk from 'chalk';
import * as Table from 'cli-table3';
import { ScanResult } from '../models/ScanResult';
import { Finding, Severity } from '../models/Finding';
import { AttackChain } from '../analysis/Deduplication';

const SEVERITY_COLORS: Record<Severity, typeof chalk.red> = {
  CRITICAL: chalk.bgRed.white,
  HIGH: chalk.red,
  MEDIUM: chalk.yellow,
  LOW: chalk.blue,
  INFO: chalk.gray,
};

const SEVERITY_ICONS: Record<Severity, string> = {
  CRITICAL: '▓▓',
  HIGH: '██',
  MEDIUM: '▓▓',
  LOW: '░░',
  INFO: '··',
};

export class TerminalReporter {
  private findingMap: Map<string, Finding> = new Map();

  printBanner(): void {
    console.log('');
    console.log(chalk.cyan('██╗     ██╗   ██╗██╗'));
    console.log(chalk.cyan('██║     ██║   ██║██║'));
    console.log(chalk.cyan('██║     ██║   ██║██║'));
    console.log(chalk.cyan('██║     ██║   ██║██║'));
    console.log(chalk.cyan('███████╗╚██████╔╝██║'));
    console.log(chalk.cyan('╚══════╝ ╚═════╝ ╚═╝'));
    console.log('');
    console.log(chalk.bold('  Lui Security Auditor'));
    console.log(chalk.gray('  AI-Powered Application Security'));
    console.log('');
  }

  printScanStart(target: string, scanType: string, technology: string): void {
    console.log(chalk.bold('Analyzing:'));
    console.log(`  ${target}`);
    console.log('');
    if (technology) {
      console.log(chalk.bold('Technology:'));
      console.log(`  ${technology}`);
      console.log('');
    }
    console.log(chalk.gray('━'.repeat(50)));
    console.log('');
  }

  printProgress(phase: string, total: number, current: number, status: string): void {
    const num = String(current).padStart(2, '0');
    const totalNum = String(total).padStart(2, '0');
    const icon = status === 'done' ? chalk.green('✓') : status === 'error' ? chalk.red('✗') : chalk.yellow('...');
    console.log(`  [${num}/${totalNum}] ${phase.padEnd(24)} ${icon}`);
  }

  printHighRiskFinding(finding: Finding): void {
    console.log('');
    console.log(chalk.red.bold(`  ⚠ ${finding.severity} RISK DETECTED`));
    console.log(`  ${finding.title}`);
    console.log(`  ${finding.id}`);
    if (finding.affectedFiles.length > 0) {
      console.log(`  ${finding.affectedFiles[0].file}${finding.affectedFiles[0].line ? ':' + finding.affectedFiles[0].line : ''}`);
    }
    console.log('');
  }

  printScanComplete(result: ScanResult): void {
    console.log(chalk.gray('━'.repeat(50)));
    console.log('');
    this.printScore(result);
    console.log('');
    this.printSummary(result);
    console.log('');
    console.log(chalk.gray('━'.repeat(50)));
    console.log('');
    this.printTopRisks(result);
    console.log('');
    console.log(chalk.gray('━'.repeat(50)));
    console.log('');
    this.printRecommendedActions(result);
    console.log('');
    
    if (result.findings.length > 0) {
      console.log(chalk.gray('Report: ./lui-report.html'));
    }
    console.log('');
    console.log(chalk.green('Lui completed the security audit.'));
    console.log('');
  }

  private printScore(result: ScanResult): void {
    console.log(chalk.bold('  SECURITY SCORE'));
    console.log('');
    
    const scoreColor = result.score >= 85 ? chalk.green : 
                       result.score >= 70 ? chalk.green :
                       result.score >= 50 ? chalk.yellow :
                       result.score >= 30 ? chalk.red :
                       chalk.bgRed.white;
    
    console.log(`                 ${scoreColor.bold(String(result.score))} / 100`);
    console.log(`                 ${chalk.gray(result.scoreLabel)}`);
  }

  private printSummary(result: ScanResult): void {
    const { summary } = result;
    const maxBar = 20;
    const maxCount = Math.max(summary.CRITICAL, summary.HIGH, summary.MEDIUM, summary.LOW, summary.INFO, 1);
    
    const rows: Array<[string, number, string]> = [
      ['CRITICAL', summary.CRITICAL, chalk.red('█')],
      ['HIGH', summary.HIGH, chalk.red('█')],
      ['MEDIUM', summary.MEDIUM, chalk.yellow('█')],
      ['LOW', summary.LOW, chalk.blue('█')],
      ['INFO', summary.INFO, chalk.gray('█')],
    ];

    for (const [label, count, char] of rows) {
      const barLength = Math.round((count / maxCount) * maxBar);
      const bar = char.repeat(barLength);
      const color = SEVERITY_COLORS[label as Severity];
      console.log(`  ${color(String(label).padEnd(10))} ${bar} ${count}`);
    }
  }

  private printTopRisks(result: ScanResult): void {
    const topFindings = result.findings
      .filter(f => f.status !== 'suppressed')
      .sort((a, b) => {
        const order: Record<Severity, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
        return order[a.severity] - order[b.severity];
      })
      .slice(0, 10);

    if (topFindings.length === 0) {
      console.log(chalk.green.bold('  No security issues found!'));
      return;
    }

    console.log(chalk.bold('  TOP SECURITY RISKS'));
    console.log('');

    for (const finding of topFindings) {
      this.findingMap.set(finding.id, finding);
      const color = SEVERITY_COLORS[finding.severity];
      const sev = String(finding.severity).padEnd(8);
      console.log(`  ${color(sev)} ${finding.id}`);
      console.log(`  ${chalk.white(finding.title)}`);
      if (finding.affectedFiles.length > 0) {
        console.log(`  ${chalk.gray(finding.affectedFiles[0].file)}${finding.affectedFiles[0].line ? chalk.gray(':') + finding.affectedFiles[0].line : ''}`);
      }
      console.log('');
    }
  }

  private printRecommendedActions(result: ScanResult): void {
    const actions = this.generateActions(result);
    if (actions.length === 0) return;

    console.log(chalk.bold('  RECOMMENDED ACTIONS'));
    console.log('');
    actions.forEach((action, i) => {
      console.log(`  ${chalk.cyan(String(i + 1) + '.')} ${action}`);
    });
  }

  private generateActions(result: ScanResult): string[] {
    const actions: string[] = [];
    const { summary } = result;

    if (summary.CRITICAL > 0) {
      actions.push('Address all CRITICAL findings immediately');
    }
    
    const secretFindings = result.findings.filter(f => f.category === 'Secrets');
    if (secretFindings.length > 0) {
      actions.push('Rotate exposed credentials and secrets');
    }

    const sqliFindings = result.findings.filter(f => f.title.includes('SQL Injection'));
    if (sqliFindings.length > 0) {
      actions.push('Fix SQL injection vulnerabilities');
    }

    const authzFindings = result.findings.filter(f => f.category === 'Authorization');
    if (authzFindings.length > 0) {
      actions.push('Review and fix authorization checks');
    }

    const depFindings = result.findings.filter(f => f.category === 'Dependencies');
    if (depFindings.length > 0) {
      actions.push('Upgrade vulnerable dependencies');
    }

    const dockerFindings = result.findings.filter(f => f.category === 'Docker Security');
    if (dockerFindings.length > 0) {
      actions.push('Review Docker security configuration');
    }

    if (summary.MEDIUM > 3) {
      actions.push('Review medium-risk findings for patterns');
    }

    return actions.slice(0, 8);
  }

  printExplain(finding: Finding): void {
    console.log('');
    console.log(chalk.bold(finding.id));
    console.log(chalk.gray('━'.repeat(40)));
    console.log('');
    console.log(chalk.bold('Title:'));
    console.log(`  ${finding.title}`);
    console.log('');
    console.log(chalk.bold('Severity:'));
    console.log(`  ${SEVERITY_COLORS[finding.severity](finding.severity)}`);
    console.log('');
    console.log(chalk.bold('Confidence:'));
    console.log(`  ${finding.confidence}`);
    console.log('');
    console.log(chalk.bold('Category:'));
    console.log(`  ${finding.category}`);
    console.log('');
    
    if (finding.affectedFiles.length > 0) {
      console.log(chalk.bold('Location:'));
      for (const file of finding.affectedFiles) {
        console.log(`  ${file.file}${file.line ? ':' + file.line : ''}`);
      }
      console.log('');
    }

    console.log(chalk.bold('Why Lui detected this:'));
    console.log(`  ${finding.description}`);
    console.log('');
    
    console.log(chalk.bold('Potential impact:'));
    console.log(`  ${finding.impact}`);
    console.log('');
    
    console.log(chalk.bold('Recommended remediation:'));
    console.log(`  ${finding.recommendation}`);
    
    if (finding.remediation) {
      console.log('');
      console.log(chalk.bold('Detailed remediation:'));
      console.log(`  ${finding.remediation}`);
    }

    if (finding.evidence.length > 0) {
      console.log('');
      console.log(chalk.bold('Evidence:'));
      for (const ev of finding.evidence) {
        console.log(`  ${chalk.gray(ev)}`);
      }
    }

    if (finding.cwe) {
      console.log('');
      console.log(chalk.bold('CWE:'));
      console.log(`  ${finding.cwe}`);
    }

    console.log('');
  }

  printFindings(findings: Finding[]): void {
    this.findingMap.clear();
    for (const f of findings) {
      this.findingMap.set(f.id, f);
    }

    const grouped = this.groupBySeverity(findings);
    
    for (const [severity, sevFindings] of Object.entries(grouped)) {
      if (sevFindings.length === 0) continue;
      console.log(chalk.bold(`  ${severity}`));
      console.log('');
      for (const finding of sevFindings) {
        console.log(`  ${SEVERITY_COLORS[severity as Severity](severity.padEnd(8))} ${finding.id}`);
        console.log(`  ${chalk.white(finding.title)}`);
        if (finding.affectedFiles.length > 0) {
          console.log(`  ${chalk.gray('Location:')} ${finding.affectedFiles[0].file}${finding.affectedFiles[0].line ? ':' + finding.affectedFiles[0].line : ''}`);
        }
        console.log('');
      }
    }
  }

  printAttackChains(chains: AttackChain[]): void {
    if (chains.length === 0) return;
    
    console.log(chalk.bold('  POTENTIAL SECURITY CHAINS'));
    console.log('');
    
    for (const chain of chains) {
      console.log(`  ${chalk.yellow('⚠')} ${chain.title}`);
      console.log(`  ${chalk.gray(chain.description)}`);
      console.log(`  ${chalk.gray('Impact:')} ${chain.impact}`);
      console.log(`  ${chalk.gray('Confidence:')} ${chain.confidence}`);
      console.log('');
    }
  }

  private groupBySeverity(findings: Finding[]): Record<string, Finding[]> {
    const grouped: Record<string, Finding[]> = {
      CRITICAL: [],
      HIGH: [],
      MEDIUM: [],
      LOW: [],
      INFO: [],
    };
    for (const finding of findings) {
      if (finding.status !== 'suppressed') {
        grouped[finding.severity].push(finding);
      }
    }
    return grouped;
  }

  getFindingById(id: string): Finding | undefined {
    return this.findingMap.get(id);
  }

  setFinding(finding: Finding): void {
    this.findingMap.set(finding.id, finding);
  }
}
