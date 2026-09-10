import chalk from 'chalk';
import * as fs from 'fs';
import * as path from 'path';
import { ProjectDiscovery } from '../discovery/ProjectDiscovery';
import { SecurityAgent, ScanOptions } from '../agent/SecurityAgent';
import { ConfigLoader } from '../config/ConfigLoader';
import { ScanResult } from '../models/ScanResult';
import { Finding } from '../models/Finding';

export interface VerifyResult {
  findingId: string;
  fixed: boolean;
  details: string[];
  previousScore: number;
  currentScore: number;
}

export async function verifyFix(
  findingId: string,
  rootPath: string
): Promise<VerifyResult> {
  const baselinePath = path.join(rootPath, '.lui-last-scan.json');
  let previousScore = 100;

  if (fs.existsSync(baselinePath)) {
    try {
      const baseline = JSON.parse(fs.readFileSync(baselinePath, 'utf-8'));
      previousScore = baseline.score || 100;
    } catch { /* ignore */ }
  }

  const configLoader = new ConfigLoader(rootPath);
  const discovery = new ProjectDiscovery(rootPath, configLoader.getExcludes());
  const project = await discovery.discover();
  const agent = new SecurityAgent(project);

  const result = await agent.scan({
    scanType: 'standard',
    excludes: configLoader.getExcludes(),
  });

  const fixedFinding = result.findings.find(f => f.id === findingId);
  const details: string[] = [];

  if (!fixedFinding || fixedFinding.status === 'suppressed') {
    details.push(`Finding ${findingId} is no longer present in the scan results.`);
    return {
      findingId,
      fixed: true,
      details,
      previousScore,
      currentScore: result.score,
    };
  }

  if (fixedFinding.type === 'confirmed' || fixedFinding.confidence === 'HIGH') {
    const location = fixedFinding.affectedFiles[0];
    if (location) {
      const content = readFileSafe(path.join(rootPath, location.file));
      if (content) {
        const lines = content.split('\n');
        const targetLine = (location.line || 1) - 1;
        const contextWindow = lines.slice(Math.max(0, targetLine - 10), Math.min(lines.length, targetLine + 10)).join('\n');

        if (hasParameterizedQuery(contextWindow)) {
          details.push('Input parameterized');
        }
        if (hasSanitization(contextWindow)) {
          details.push('Sanitization applied');
        }
        if (fixedFinding.title.includes('SQL Injection') && hasParameterizedQuery(contextWindow)) {
          details.push('Data flow no longer reaches unsafe SQL construction');
        }
      }
    }
  }

  if (details.length === 0) {
    details.push(`Finding ${findingId} still present in codebase.`);
  }

  return {
    findingId,
    fixed: false,
    details,
    previousScore,
    currentScore: result.score,
  };
}

function readFileSafe(filePath: string): string | null {
  try {
    return fs.readFileSync(filePath, 'utf-8');
  } catch {
    return null;
  }
}

function hasParameterizedQuery(context: string): boolean {
  return /(?:\?|%s|:\w+|placeholder|parameterized|prepared|preparedStatement)/i.test(context);
}

function hasSanitization(context: string): boolean {
  return /(?:sanitize|escape|validate|encode|clean|xss|purify)/i.test(context);
}

export function printVerifyResult(result: VerifyResult): void {
  console.log('');
  console.log(chalk.bold(`  Verifying ${result.findingId}...`));
  console.log(chalk.gray('  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
  console.log('');

  if (result.fixed) {
    console.log(chalk.green.bold(`  ✓ ${result.findingId} FIXED`));
  } else {
    console.log(chalk.red.bold(`  ✗ ${result.findingId} NOT FIXED`));
  }

  console.log('');
  for (const detail of result.details) {
    console.log(`  ${result.fixed ? chalk.green('✓') : chalk.red('✗')} ${detail}`);
  }

  console.log('');
  console.log(chalk.bold('  Security Score:'));
  const change = result.currentScore - result.previousScore;
  const changeStr = change >= 0 ? `↑ +${change}` : `↓ ${change}`;
  const changeColor = change >= 0 ? chalk.green : chalk.red;
  console.log(`  ${result.previousScore} → ${result.currentScore} ${changeColor(changeStr)}`);
  console.log('');
}
