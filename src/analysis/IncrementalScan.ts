import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';

export interface ChangedFile {
  path: string;
  status: 'added' | 'modified' | 'deleted' | 'renamed';
  oldPath?: string;
}

export interface IncrementalScanPlan {
  changedFiles: ChangedFile[];
  dependentModules: string[];
  shouldScan: boolean;
  reason: string;
}

export function detectChanges(rootPath: string): IncrementalScanPlan {
  const changedFiles: ChangedFile[] = [];
  const dependentModules: string[] = [];

  try {
    const gitDir = path.join(rootPath, '.git');
    if (!fs.existsSync(gitDir)) {
      return { changedFiles: [], dependentModules: [], shouldScan: true, reason: 'Not a git repository - full scan required' };
    }

    const output = execSync('git diff --name-status HEAD~1 HEAD 2>nul || git diff --name-status', {
      cwd: rootPath,
      encoding: 'utf-8',
      timeout: 10000,
    });

    for (const line of output.trim().split('\n')) {
      if (!line.trim()) continue;
      const parts = line.split('\t');
      if (parts.length < 2) continue;

      const status = mapGitStatus(parts[0]);
      const filePath = parts[1];

      if (isExcludedFile(filePath)) continue;

      changedFiles.push({
        path: filePath,
        status,
        oldPath: parts[2],
      });
    }
  } catch { /* git command failed */ }

  const moduleFiles = changedFiles.filter(f =>
    f.path.endsWith('package.json') || f.path.endsWith('requirements.txt') || f.path.endsWith('Cargo.toml')
  );
  for (const f of moduleFiles) {
    dependentModules.push(f.path);
  }

  const sourceChanges = changedFiles.filter(f =>
    /\.(js|ts|py|java|go|rb|php)$/.test(f.path)
  );

  const shouldScan = sourceChanges.length > 0 || moduleFiles.length > 0 || changedFiles.length === 0;
  const reason = changedFiles.length === 0
    ? 'No changes detected'
    : `${changedFiles.length} changed file(s), ${sourceChanges.length} source file(s)`;

  return { changedFiles, dependentModules, shouldScan, reason };
}

function mapGitStatus(status: string): ChangedFile['status'] {
  if (status === 'A') return 'added';
  if (status === 'D') return 'deleted';
  if (status === 'R') return 'renamed';
  return 'modified';
}

function isExcludedFile(filePath: string): boolean {
  const excluded = ['node_modules', '.git', 'dist', 'build', '__pycache__', 'coverage', '.next'];
  return excluded.some(ex => filePath.includes(ex));
}

export function printIncrementalPlan(plan: IncrementalScanPlan): void {
  const chalk = require('chalk');
  console.log('');
  console.log(chalk.bold('  Incremental Scan'));
  console.log(chalk.gray('  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
  console.log('');

  if (plan.changedFiles.length === 0) {
    console.log(chalk.gray('  No changes detected since last scan.'));
    console.log('');
    return;
  }

  console.log(chalk.bold(`  ${plan.changedFiles.length} changed file(s):`));
  for (const f of plan.changedFiles) {
    const icon = f.status === 'added' ? chalk.green('+') :
                 f.status === 'deleted' ? chalk.red('-') :
                 f.status === 'renamed' ? chalk.yellow('→') :
                 chalk.yellow('~');
    console.log(`  ${icon} ${f.path}`);
  }
  console.log('');

  if (plan.dependentModules.length > 0) {
    console.log(chalk.bold(`  ${plan.dependentModules.length} module change(s):`));
    for (const m of plan.dependentModules) {
      console.log(`  ${chalk.cyan('!')} ${m}`);
    }
    console.log('');
  }

  console.log(`  ${plan.reason}`);
  console.log('');
}
