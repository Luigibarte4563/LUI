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
import { printDeveloperReport } from './reporters/DeveloperReporter';
import { ScanResult } from './models/ScanResult';
import { Finding } from './models/Finding';
import { buildAttackSurface, printAttackSurface } from './commands/map';
import { investigateProject, printInvestigateResults } from './commands/investigate';
import { verifyFix, printVerifyResult } from './commands/verify';
import { loadLifecycleStore, updateFindingStatus, formatLifecycle, getLifecycleHistory } from './analysis/Lifecycle';
import { generateSecurityTest, formatGeneratedTest } from './analysis/TestGenerator';
import { buildDependencyGraph, formatDependencyGraph } from './analysis/DependencyGraph';
import { generateRotationGuidance, formatRotationGuidance } from './analysis/SecretRotation';
import { getProfile, listProfiles } from './config/Profiles';
import { loadPolicy, evaluatePolicy, formatPolicyEvaluation } from './config/PolicyEngine';
import { askLuiDynamic, printAskResponse } from './commands/ask';
import { detectChanges, printIncrementalPlan } from './analysis/IncrementalScan';
import { buildContextGraph, formatContextGraph } from './analysis/ContextGraph';

const VERSION = '0.2.0';

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
  .option('-p, --profile <profile>', 'Security profile (startup, webapp, api, enterprise, ci, mobile, docker)')
  .option('--developer', 'Developer-friendly output with code suggestions')
  .option('--incremental', 'Only scan changed files since last git commit')
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

    // Apply profile if specified
    let scanType = options.quick ? 'quick' : options.deep ? 'deep' : 'standard';
    let category = options.category as string | undefined;

    if (options.profile) {
      const profile = getProfile(options.profile as string);
      if (!profile) {
        console.error(chalk.red(`  Error: Unknown profile "${options.profile}". Available: ${listProfiles().map(p => p.name).join(', ')}`));
        process.exit(2);
      }
      scanType = profile.scanType;
      console.log(chalk.cyan(`  Using profile: ${profile.name} - ${profile.description}`));
    }

    const format = (options.format as string) || 'terminal';

    try {
      // Incremental scan detection
      if (options.incremental) {
        const plan = detectChanges(resolvedPath);
        printIncrementalPlan(plan);
        if (!plan.shouldScan) {
          console.log(chalk.green('  No changes to scan.'));
          process.exit(0);
        }
      }

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

      const scanOptions: ScanOptions = {
        scanType: scanType as 'quick' | 'standard' | 'deep',
        category,
        url: options.url as string | undefined,
        excludes: configLoader.getExcludes(),
        ai: configLoader.getConfig().ai,
        privacy: configLoader.getConfig().privacy,
        profile: options.profile as string | undefined,
        incremental: options.incremental as boolean,
        developer: options.developer as boolean,
        dynamicCve: configLoader.getConfig().security?.dynamic_cve === true,
      };
      let result = await agent.scan(scanOptions);

      // Apply ignores from .luiignore
      const ignored = loadIgnoredFindings();
      const ignoredCount = result.findings.filter((f: any) => ignored[f.id]).length;
      if (ignoredCount > 0) {
        result = {
          ...result,
          findings: result.findings.filter((f: any) => !ignored[f.id]),
        };
      }

      // Evaluate policy
      const policyConfig = loadPolicy(resolvedPath);
      const policyEval = evaluatePolicy(result, policyConfig);

      // Output
      if (format === 'json') {
        const jsonReporter = new JSONReporter();
        console.log(jsonReporter.generate(result));
      } else if (format === 'markdown') {
        const mdReporter = new MarkdownReporter();
        console.log(mdReporter.generate(result));
      } else {
        if (options.developer) {
          printDeveloperReport(result.findings);
        } else {
          reporter.printScanComplete(result);
        }
        
        if (result.attackChains && result.attackChains.length > 0) {
          reporter.printAttackChains(result.attackChains as any);
        }

        // Print policy evaluation
        if (!policyEval.passed || policyEval.warnings.length > 0) {
          console.log('');
          console.log(chalk.bold('  POLICY EVALUATION'));
          console.log(chalk.gray('  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
          console.log(formatPolicyEvaluation(policyEval));
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
  .description('Explain a specific security finding with data flow evidence')
  .action(async (id: string) => {
    const reporter = new TerminalReporter();
    
    const finding = findFindingById(id);
    if (finding) {
      reporter.printExplain(finding);

      // Dynamic: if the finding has LLM-enriched analysis, show it
      if (finding.aiAnalysis?.enrichedDescription) {
        console.log(chalk.bold('  AI ENRICHED ANALYSIS'));
        console.log(chalk.gray('  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
        console.log('');
        console.log(`  ${finding.aiAnalysis.enrichedDescription}`);
        if (finding.aiAnalysis.exploitScenario) {
          console.log('');
          console.log(chalk.bold('  Exploitation scenario:'));
          console.log(`  ${finding.aiAnalysis.exploitScenario}`);
        }
        if (finding.aiAnalysis.remediationSteps.length > 0) {
          console.log('');
          console.log(chalk.bold('  Recommended fixes:'));
          finding.aiAnalysis.remediationSteps.forEach((step, i) => {
            console.log(`  ${i + 1}. ${step}`);
          });
        }
        if (finding.aiAnalysis.falsePositiveReason) {
          console.log('');
          console.log(chalk.yellow(`  ⚠ Possibly a false positive: ${finding.aiAnalysis.falsePositiveReason}`));
        }
        console.log('');
      }

      // Feature 1: Evidence explanation
      const lastResult = loadLastScanResult();
      if (lastResult?.metadata?.evidenceExplanations) {
        const explanations = lastResult.metadata.evidenceExplanations as Array<{
          findingId: string;
          dataFlowSteps: Array<{ label: string; detail: string; line?: number; file?: string; type: string }>;
          sanitizationStatus: string;
          confidenceReason: string;
        }>;
        const explanation = explanations.find(e => e.findingId === id);
        if (explanation) {
          console.log(chalk.bold('  DATA FLOW EVIDENCE'));
          console.log(chalk.gray('  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
          console.log('');
          for (const step of explanation.dataFlowSteps) {
            console.log(`  ${step.label}`);
            console.log(`    ${step.detail}`);
            if (step.file && step.line) {
              console.log(chalk.gray(`    ${step.file}:${step.line}`));
            }
            console.log('        ↓');
          }
          console.log('');
          console.log(`  Sanitization: ${explanation.sanitizationStatus}`);
          console.log('');
          console.log(`  ${explanation.confidenceReason}`);
          console.log('');
        }
      }
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

      // Feature 5: Secret rotation guidance
      const rotation = generateRotationGuidance(finding);
      if (rotation) {
        console.log('');
        console.log(chalk.bold('  Secret Rotation Guidance:'));
        console.log(formatRotationGuidance(rotation));
      }
      console.log('');
    } else {
      console.log(chalk.yellow(`  Finding ${id} not found. Run a scan first.`));
    }
  });

// Map command
program
  .command('map [path]')
  .description('Show attack surface map of the application')
  .action(async (targetPath: string) => {
    const target = targetPath || process.cwd();
    const resolvedPath = path.resolve(target);

    const lastResult = loadLastScanResult();
    if (!lastResult) {
      console.log(chalk.yellow('  No scan results found. Run "lui scan" first.'));
      return;
    }

    const surface = buildAttackSurface(lastResult);
    printAttackSurface(surface);
  });

// Investigate command
program
  .command('investigate [path]')
  .description('Investigate security incident indicators')
  .action((targetPath: string) => {
    const target = targetPath || process.cwd();
    const resolvedPath = path.resolve(target);

    if (!fs.existsSync(resolvedPath)) {
      console.error(chalk.red(`  Error: Path "${resolvedPath}" does not exist.`));
      process.exit(2);
    }

    console.log(chalk.bold('  Investigating security indicators...'));
    console.log('');

    const indicators = investigateProject(resolvedPath);
    printInvestigateResults(indicators);
  });

// Verify command
program
  .command('verify <id>')
  .description('Verify if a security fix was applied')
  .action(async (id: string) => {
    const result = await verifyFix(id, process.cwd());
    printVerifyResult(result);
  });

// Test command
program
  .command('test <id>')
  .description('Generate a security regression test for a finding')
  .action((id: string) => {
    const finding = findFindingById(id);
    if (!finding) {
      console.log(chalk.yellow(`  Finding ${id} not found. Run a scan first.`));
      return;
    }

    const test = generateSecurityTest(finding);
    console.log('');
    console.log(chalk.bold('  Generated Security Test'));
    console.log(chalk.gray('  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
    console.log('');
    console.log(formatGeneratedTest(test));
    console.log('');
  });

// Deps command
program
  .command('deps [path]')
  .description('Show dependency graph with vulnerability analysis')
  .action((targetPath: string) => {
    const target = targetPath || process.cwd();
    const resolvedPath = path.resolve(target);

    const lastResult = loadLastScanResult();
    const findings = lastResult?.findings || [];

    const graph = buildDependencyGraph(resolvedPath, findings);
    console.log('');
    console.log(formatDependencyGraph(graph));
    console.log('');
  });

// Secrets history command
program
  .command('secrets history')
  .description('Check git history for previously committed secrets')
  .action(() => {
    console.log('');
    console.log(chalk.bold('  Secret History Analysis'));
    console.log(chalk.gray('  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
    console.log('');
    console.log(chalk.gray('  Checking git history for previously committed secrets...'));
    console.log('');
    console.log(chalk.yellow('  ⚠  This will analyze git history without printing secrets.'));
    console.log('');
    console.log('  Recommended steps:');
    console.log('  1. Run: git log --all --oneline -- "*.env" "*.pem" "*.key"');
    console.log('  2. Run: git log -p --all -S "password=" -- "*.env" "*.js" | head -50');
    console.log('  3. Check CI/CD logs for exposed credentials');
    console.log('  4. Check deployment environments');
    console.log('');
    console.log(chalk.gray('  Tip: Use "lui scan" to find currently exposed secrets.'));
    console.log('');
  });

// Lifecycle command
program
  .command('lifecycle <id> <status>')
  .description('Update finding lifecycle status')
  .action((id: string, status: string) => {
    const validStatuses = ['new', 'confirmed', 'acknowledged', 'fix_in_progress', 'fixed', 'verified', 'false_positive', 'accepted_risk'];
    if (!validStatuses.includes(status)) {
      console.log(chalk.red(`  Invalid status: ${status}`));
      console.log(chalk.gray(`  Valid statuses: ${validStatuses.join(', ')}`));
      return;
    }

    const store = loadLifecycleStore(process.cwd());
    const updated = updateFindingStatus(store, id, status as any);
    const storePath = path.join(process.cwd(), '.lui-lifecycle.json');
    fs.writeFileSync(storePath, JSON.stringify(updated, null, 2), 'utf-8');

    const lifecycle = getLifecycleHistory(updated, id);
    if (lifecycle) {
      console.log('');
      console.log(chalk.bold(`  Lifecycle updated for ${id}`));
      console.log('');
      console.log(formatLifecycle(lifecycle));
    }
    console.log('');
  });

// Ask command
program
  .command('ask [question...]')
  .description('Ask Lui security questions (uses LLM when AI is enabled)')
  .action(async (questionParts: string[]) => {
    const question = questionParts.join(' ') || 'help';
    const result = loadLastScanResult();
    const configLoader = new ConfigLoader(process.cwd());
    const ai = configLoader.getConfig().ai;
    const privacy = configLoader.getConfig().privacy;
    const response = await askLuiDynamic(question, result, ai, privacy);
    printAskResponse(response);
  });

// Profiles command
program
  .command('profiles')
  .description('List available security profiles')
  .action(() => {
    const profiles = listProfiles();
    console.log('');
    console.log(chalk.bold('  Security Profiles'));
    console.log(chalk.gray('  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
    console.log('');

    for (const profile of profiles) {
      console.log(chalk.bold(`  ${profile.name}`));
      console.log(`    ${profile.description}`);
      console.log(`    Scan type: ${profile.scanType} | Fail on: ${profile.failOn}`);
      console.log(`    Categories: ${profile.categories.join(', ')}`);
      console.log('');
    }

    console.log(chalk.gray('  Usage: lui scan --profile <name>'));
    console.log('');
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

    // Score comparison
    if (baseline.score !== undefined) {
      const change = lastResult.score - baseline.score;
      const changeStr = change >= 0 ? `↑ +${change}` : `↓ ${change}`;
      const changeColor = change >= 0 ? chalk.green : chalk.red;
      console.log(chalk.bold('  Score Change:'));
      console.log(`  ${baseline.score} → ${lastResult.score} ${changeColor(changeStr)}`);
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
