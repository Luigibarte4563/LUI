#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import * as fs from 'fs';
import * as path from 'path';
import { ProjectDiscovery } from './discovery/ProjectDiscovery';
import { SecurityAgent, ScanOptions, ScanProgress } from './agent/SecurityAgent';
import { ConfigLoader } from './config/ConfigLoader';
import { TerminalReporter } from './reporters/TerminalReporter';
import { JSONReporter } from './reporters/JSONReporter';
import { MarkdownReporter } from './reporters/MarkdownReporter';
import { HTMLReporter } from './reporters/HTMLReporter';
import { ScanResult } from './models/ScanResult';
import { Finding } from './models/Finding';

const VERSION = '0.1.0';

const program = new Command();

program
  .name('lui')
  .description('Lui Security Auditor - AI-Powered Application Security')
  .version(VERSION);

// Scan command
program
  .command('scan [path]')
  .description('Scan a project for security vulnerabilities')
  .option('-q, --quick', 'Run quick scan (secrets, dependencies, basic SAST)')
  .option('-d, --deep', 'Run deep scan (all scanners with data flow analysis)')
  .option('-c, --category <category>', 'Scan specific category (secrets, dependencies, code, auth, authorization, api, configuration, docker, cicd, web)')
  .option('-u, --url <url>', 'Scan a running web application URL')
  .option('-f, --format <format>', 'Output format (terminal, json, markdown)', 'terminal')
  .action(async (targetPath: string, options: Record<string, unknown>) => {
    const reporter = new TerminalReporter();
    reporter.printBanner();

    const target = targetPath || process.cwd();
    const resolvedPath = path.resolve(target);

    if (!fs.existsSync(resolvedPath)) {
      console.error(chalk.red(`  Error: Path "${resolvedPath}" does not exist.`));
      process.exit(2);
    }

    // URL scanning requires confirmation
    if (options.url) {
      const confirmed = await confirmUrlScan(options.url as string);
      if (!confirmed) {
        console.log(chalk.yellow('  Scan cancelled.'));
        process.exit(0);
      }
    }

    const scanType = options.quick ? 'quick' : options.deep ? 'deep' : 'standard';
    const category = options.category as string | undefined;
    const format = (options.format as string) || 'terminal';

    try {
      // Discover project
      console.log(chalk.bold('  Discovering project...'));
      const configLoader = new ConfigLoader(resolvedPath);
      const discovery = new ProjectDiscovery(resolvedPath, configLoader.getExcludes());
      const project = await discovery.discover();

      const techStr = [
        ...project.technology.languages,
        ...project.technology.frameworks,
      ].join(' + ') || 'Unknown';

      reporter.printScanStart(resolvedPath, scanType, techStr);

      // Create agent and scan
      const agent = new SecurityAgent(project);
      
      agent.onProgress((progress: ScanProgress) => {
        if (progress.finding && (progress.finding.severity === 'CRITICAL' || progress.finding.severity === 'HIGH')) {
          reporter.printHighRiskFinding(progress.finding);
        }
      });

      const options2: ScanOptions = {
        scanType: scanType as 'quick' | 'standard' | 'deep',
        category,
        url: options.url as string | undefined,
        excludes: configLoader.getExcludes(),
        ai: configLoader.getConfig().ai,
        privacy: configLoader.getConfig().privacy,
      };
      let result = await agent.scan(options2);

      // Apply ignores from .luiignore
      const ignored = loadIgnoredFindings();
      const ignoredCount = result.findings.filter((f: any) => ignored[f.id]).length;
      if (ignoredCount > 0) {
        result = {
          ...result,
          findings: result.findings.filter((f: any) => !ignored[f.id]),
        };
      }

      // Output
      if (format === 'json') {
        const jsonReporter = new JSONReporter();
        console.log(jsonReporter.generate(result));
      } else if (format === 'markdown') {
        const mdReporter = new MarkdownReporter();
        console.log(mdReporter.generate(result));
      } else {
        reporter.printScanComplete(result);
        
        if (result.attackChains && result.attackChains.length > 0) {
          reporter.printAttackChains(result.attackChains as any);
        }

        // Generate HTML report
        const htmlReporter = new HTMLReporter();
        const htmlPath = path.join(resolvedPath, 'lui-report.html');
        try {
          fs.writeFileSync(htmlPath, htmlReporter.generate(result), 'utf-8');
        } catch { /* ignore */ }
      }

      // Save last scan result for report/explain/baseline commands
      saveLastScanResult(result);

      // CI/CD exit code
      const config = configLoader.getConfig();
      const failOn = config.policy?.fail_on || 'high';
      const exitCode = getExitCode(result, failOn);
      process.exit(exitCode);

    } catch (error) {
      console.error(chalk.red(`  Error: ${(error as Error).message}`));
      process.exit(2);
    }
  });

// Explain command
program
  .command('explain <id>')
  .description('Explain a specific security finding')
  .action((id: string) => {
    const reporter = new TerminalReporter();
    
    // Try to find the finding in the last scan results
    const finding = findFindingById(id);
    if (finding) {
      reporter.printExplain(finding);
    } else {
      console.log(chalk.yellow(`  Finding ${id} not found. Run a scan first.`));
      console.log('');
      console.log(chalk.gray('  Tip: Run "lui scan" first, then "lui explain <id>"'));
    }
  });

// Fix command
program
  .command('fix <id>')
  .description('Show remediation guidance for a finding')
  .action((id: string) => {
    const finding = findFindingById(id);
    if (finding) {
      console.log('');
      console.log(chalk.bold(`  Remediation for ${finding.id}`));
      console.log(chalk.gray('━'.repeat(40)));
      console.log('');
      console.log(chalk.bold('  Finding:'));
      console.log(`  ${finding.title}`);
      console.log('');
      console.log(chalk.bold('  What is wrong:'));
      console.log(`  ${finding.description}`);
      console.log('');
      console.log(chalk.bold('  Why it matters:'));
      console.log(`  ${finding.impact}`);
      console.log('');
      console.log(chalk.bold('  How to fix:'));
      console.log(`  ${finding.recommendation}`);
      if (finding.remediation) {
        console.log('');
        console.log(chalk.bold('  Detailed steps:'));
        console.log(`  ${finding.remediation}`);
      }
      console.log('');
    } else {
      console.log(chalk.yellow(`  Finding ${id} not found. Run a scan first.`));
    }
  });

// Report command
program
  .command('report')
  .description('Generate a security report')
  .option('-f, --format <format>', 'Report format (json, html, markdown)', 'html')
  .option('-o, --output <path>', 'Output file path')
  .action((options: Record<string, string>) => {
    const format = options.format || 'html';
    const outputPath = options.output;
    
    console.log(chalk.bold('  Generating security report...'));
    
    // Try to load last scan result
    const lastResult = loadLastScanResult();
    if (!lastResult) {
      console.log(chalk.yellow('  No scan results found. Run "lui scan" first.'));
      return;
    }

    let output: string;
    let defaultFilename: string;

    switch (format) {
      case 'json': {
        const reporter = new JSONReporter();
        output = reporter.generate(lastResult);
        defaultFilename = 'lui-report.json';
        break;
      }
      case 'markdown': {
        const reporter = new MarkdownReporter();
        output = reporter.generate(lastResult);
        defaultFilename = 'SECURITY-REPORT.md';
        break;
      }
      default: {
        const reporter = new HTMLReporter();
        output = reporter.generate(lastResult);
        defaultFilename = 'lui-report.html';
        break;
      }
    }

    const filePath = outputPath || path.join(process.cwd(), defaultFilename);
    fs.writeFileSync(filePath, output, 'utf-8');
    console.log(chalk.green(`  Report saved to: ${filePath}`));
  });

// Baseline command
program
  .command('baseline')
  .description('Save current scan results as baseline')
  .action(() => {
    const lastResult = loadLastScanResult();
    if (!lastResult) {
      console.log(chalk.yellow('  No scan results found. Run "lui scan" first.'));
      return;
    }

    const baselinePath = path.join(process.cwd(), '.lui-baseline.json');
    const baselineData = {
      scanDate: lastResult.scanDate,
      score: lastResult.score,
      findings: lastResult.findings.map((f: Finding) => ({
        id: f.id,
        severity: f.severity,
        title: f.title,
        file: f.affectedFiles[0]?.file || '',
      })),
    };

    fs.writeFileSync(baselinePath, JSON.stringify(baselineData, null, 2), 'utf-8');
    console.log(chalk.green(`  Baseline saved to: ${baselinePath}`));
  });

// Diff command
program
  .command('diff')
  .description('Compare current scan with baseline')
  .action(() => {
    const baselinePath = path.join(process.cwd(), '.lui-baseline.json');
    if (!fs.existsSync(baselinePath)) {
      console.log(chalk.yellow('  No baseline found. Run "lui baseline" first.'));
      return;
    }

    const lastResult = loadLastScanResult();
    if (!lastResult) {
      console.log(chalk.yellow('  No current scan results. Run "lui scan" first.'));
      return;
    }

    const baseline = JSON.parse(fs.readFileSync(baselinePath, 'utf-8'));
    const currentIds = new Set(lastResult.findings.map((f: Finding) => `${f.id}|${f.title}`));
    const baselineIds = new Set(baseline.findings.map((f: { id: string; title: string }) => `${f.id}|${f.title}`));

    const newFindings = lastResult.findings.filter((f: Finding) => !baselineIds.has(`${f.id}|${f.title}`));
    const fixedFindings = baseline.findings.filter((f: { id: string; title: string }) => !currentIds.has(`${f.id}|${f.title}`));

    console.log('');
    console.log(chalk.bold('  Security Diff'));
    console.log(chalk.gray('━'.repeat(40)));
    console.log('');
    
    if (newFindings.length > 0) {
      console.log(chalk.red.bold('  NEW FINDINGS'));
      for (const f of newFindings) {
        console.log(`    ${f.severity.padEnd(8)} ${f.id}  ${f.title}`);
      }
      console.log('');
    }

    if (fixedFindings.length > 0) {
      console.log(chalk.green.bold('  FIXED'));
      for (const f of fixedFindings) {
        console.log(`    ${f.id}  ${f.title}`);
      }
      console.log('');
    }

    if (newFindings.length === 0 && fixedFindings.length === 0) {
      console.log(chalk.green('  No changes from baseline.'));
    }

    console.log('');
  });

// Ignore command
program
  .command('ignore <id>')
  .description('Suppress a finding')
  .action((id: string) => {
    const readline = require('readline');
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    
    rl.question('  Reason for ignoring: ', (reason: string) => {
      rl.close();
      
      if (!reason.trim()) {
        console.log(chalk.red('  A reason is required.'));
        return;
      }

      const ignorePath = path.join(process.cwd(), '.luiignore');
      const ignores = loadIgnoredFindings();
      
      ignores[id] = reason;
      fs.writeFileSync(ignorePath, JSON.stringify(ignores, null, 2), 'utf-8');
      
      console.log('');
      console.log(chalk.green(`  Ignored: ${id}`));
      console.log(chalk.gray(`  Reason: ${reason}`));
      console.log('');
    });
  });

// Config command
program
  .command('config')
  .description('Show or update Lui configuration')
  .action(() => {
    const configPath = path.join(process.cwd(), '.lui.yml');
    
    if (fs.existsSync(configPath)) {
      console.log(chalk.bold('  Current configuration:'));
      console.log('');
      console.log(fs.readFileSync(configPath, 'utf-8'));
    } else {
      console.log(chalk.bold('  No .lui.yml found in current directory.'));
      console.log('');
      console.log(chalk.gray('  Create a .lui.yml file to customize Lui:'));
      console.log('');
      console.log(chalk.gray('  project:'));
      console.log(chalk.gray('    name: my-project'));
      console.log(chalk.gray('  scan:'));
      console.log(chalk.gray('    depth: standard'));
      console.log(chalk.gray('  exclude:'));
      console.log(chalk.gray('    - node_modules'));
      console.log(chalk.gray('    - vendor'));
      console.log(chalk.gray('  security:'));
      console.log(chalk.gray('    secrets: true'));
      console.log(chalk.gray('    dependencies: true'));
      console.log(chalk.gray('    sast: true'));
      console.log('');
    }
  });

// Helper functions
function loadIgnoredFindings(): Record<string, string> {
  const ignorePath = path.join(process.cwd(), '.luiignore');
  if (fs.existsSync(ignorePath)) {
    try {
      return JSON.parse(fs.readFileSync(ignorePath, 'utf-8'));
    } catch { /* ignore */ }
  }
  return {};
}

function confirmUrlScan(url: string): Promise<boolean> {
  return new Promise((resolve) => {
    const readline = require('readline');
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    
    console.log('');
    console.log(chalk.yellow.bold('  Authorization required.'));
    console.log('');
    console.log('  You are about to perform active security checks against:');
    console.log('');
    console.log(chalk.bold(`  ${url}`));
    console.log('');
    console.log('  Only continue if you own or are authorized to test this application.');
    console.log('');
    
    rl.question('  Continue? [y/N] ', (answer: string) => {
      rl.close();
      resolve(answer.toLowerCase() === 'y');
    });
  });
}

function findFindingById(id: string): Finding | null {
  // Try to load from last scan result
  const result = loadLastScanResult();
  if (result) {
    return result.findings.find((f: Finding) => f.id === id) || null;
  }
  return null;
}

function loadLastScanResult(): ScanResult | null {
  const resultPath = path.join(process.cwd(), '.lui-last-scan.json');
  if (fs.existsSync(resultPath)) {
    try {
      return JSON.parse(fs.readFileSync(resultPath, 'utf-8'));
    } catch { /* ignore */ }
  }
  return null;
}

function saveLastScanResult(result: ScanResult): void {
  const resultPath = path.join(process.cwd(), '.lui-last-scan.json');
  try {
    fs.writeFileSync(resultPath, JSON.stringify(result, null, 2), 'utf-8');
  } catch { /* ignore */ }
}

function getExitCode(result: ScanResult, failOn: string): number {
  const severityOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  const threshold = severityOrder[failOn] || 3;
  
  for (const finding of result.findings) {
    if (finding.status === 'suppressed') continue;
    const findingLevel = severityOrder[finding.severity.toLowerCase()];
    if (findingLevel >= threshold) return 1;
  }
  return 0;
}

program.parse();
