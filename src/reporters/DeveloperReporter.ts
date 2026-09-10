import chalk from 'chalk';
import { Finding, FileLocation } from '../models/Finding';

export function printDeveloperFinding(finding: Finding): void {
  const location = finding.affectedFiles[0];

  console.log('');
  if (location) {
    console.log(chalk.bold(`  ${location.file}${location.line ? ':' + location.line : ''}`));
  }

  console.log('');
  console.log(chalk.bold('  Unsafe:'));
  printCodeSnippet(finding, location);

  console.log('');
  console.log(chalk.bold('  Suggested:'));
  printSuggestedFix(finding);

  console.log('');
  console.log(chalk.gray(`  ${finding.id} | ${finding.severity} | ${finding.category}`));
  if (finding.cwe) {
    console.log(chalk.gray(`  CWE: ${finding.cwe}`));
  }
  console.log('');
}

function printCodeSnippet(finding: Finding, location: FileLocation | undefined): void {
  if (!location || !location.snippet) {
    console.log(chalk.red(`    // ${finding.description}`));
    return;
  }

  const lines = location.snippet.split('\n');
  for (const line of lines) {
    console.log(chalk.red(`    ${line}`));
  }
}

function printSuggestedFix(finding: Finding): void {
  const category = finding.category.toLowerCase();

  if (category.includes('injection') || finding.title.includes('SQL')) {
    console.log(chalk.green('    // Use parameterized queries:'));
    console.log(chalk.green('    db.query("SELECT * FROM users WHERE id = ?", [userId])'));
  } else if (category.includes('xss') || finding.title.includes('XSS')) {
    console.log(chalk.green('    // Escape output:'));
    console.log(chalk.green('    res.send(escapeHtml(userInput))'));
  } else if (category.includes('command') || finding.title.includes('Command')) {
    console.log(chalk.green('    // Validate and sanitize input:'));
    console.log(chalk.green('    const sanitized = validateHostname(host)'));
    console.log(chalk.green('    exec(`ping -c 4 ${sanitized}`)'));
  } else if (category.includes('secret') || finding.title.includes('credential')) {
    console.log(chalk.green('    // Use environment variables:'));
    console.log(chalk.green('    const key = process.env.API_KEY'));
  } else if (category.includes('path') || finding.title.includes('Path')) {
    console.log(chalk.green('    // Use path.resolve with validation:'));
    console.log(chalk.green('    const safePath = path.resolve(baseDir, userInput)'));
    console.log(chalk.green('    if (!safePath.startsWith(baseDir)) throw new Error("Invalid path")'));
  } else if (finding.recommendation) {
    console.log(chalk.green(`    // ${finding.recommendation}`));
  } else {
    console.log(chalk.green(`    // Review and fix: ${finding.title}`));
  }
}

export function printDeveloperReport(findings: Finding[]): void {
  const grouped = {
    CRITICAL: findings.filter(f => f.severity === 'CRITICAL'),
    HIGH: findings.filter(f => f.severity === 'HIGH'),
    MEDIUM: findings.filter(f => f.severity === 'MEDIUM'),
    LOW: findings.filter(f => f.severity === 'LOW'),
  };

  for (const [severity, items] of Object.entries(grouped)) {
    if (items.length === 0) continue;
    console.log(chalk.bold(`\n  ${severity} (${items.length})`));
    for (const finding of items) {
      printDeveloperFinding(finding);
    }
  }
}
