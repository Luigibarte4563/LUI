import * as fs from 'fs';
import * as path from 'path';
import { z } from 'zod';
import { Finding, Severity } from '../models/Finding';
import { ScanResult } from '../models/ScanResult';

const PolicyRuleSchema = z.object({
  severity: z.string(),
  action: z.enum(['fail', 'warn', 'ignore']),
  categories: z.array(z.string()).optional(),
  message: z.string().optional(),
});

const PolicySchema = z.object({
  policy: z.object({
    rules: z.array(PolicyRuleSchema).optional(),
    fail_on: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional(),
    max_critical: z.number().optional(),
    max_high: z.number().optional(),
    max_medium: z.number().optional(),
    max_low: z.number().optional(),
  }).optional(),
});

export type PolicyRule = z.infer<typeof PolicyRuleSchema>;
export type PolicyConfig = z.infer<typeof PolicySchema>;

export interface PolicyViolation {
  rule: PolicyRule;
  findings: Finding[];
  message: string;
}

export interface PolicyEvaluation {
  passed: boolean;
  violations: PolicyViolation[];
  warnings: PolicyViolation[];
}

const DEFAULT_RULES: PolicyRule[] = [
  { severity: 'CRITICAL', action: 'fail', message: 'Critical vulnerabilities must be resolved' },
  { severity: 'HIGH', action: 'fail', message: 'High-severity vulnerabilities must be resolved' },
  { severity: 'MEDIUM', action: 'warn', message: 'Medium-severity vulnerabilities should be reviewed' },
  { severity: 'LOW', action: 'ignore' },
  { severity: 'INFO', action: 'ignore' },
];

export function loadPolicy(rootPath: string): PolicyConfig {
  const policyFiles = ['.lui-policy.yml', '.lui-policy.yaml', '.lui-policy.json'];
  for (const file of policyFiles) {
    const filePath = path.join(rootPath, file);
    if (fs.existsSync(filePath)) {
      try {
        const content = fs.readFileSync(filePath, 'utf-8');
        let parsed: unknown;
        if (file.endsWith('.json')) {
          parsed = JSON.parse(content);
        } else {
          const yaml = require('yaml');
          parsed = yaml.parse(content);
        }
        const result = PolicySchema.safeParse(parsed);
        if (result.success) return result.data;
      } catch { /* ignore */ }
    }
  }
  return {};
}

export function evaluatePolicy(
  result: ScanResult,
  config: PolicyConfig
): PolicyEvaluation {
  const rules = config.policy?.rules || DEFAULT_RULES;
  const violations: PolicyViolation[] = [];
  const warnings: PolicyViolation[] = [];

  for (const rule of rules) {
    const matchingFindings = result.findings.filter(f => {
      if (f.status === 'suppressed') return false;
      if (f.severity !== rule.severity) return false;
      if (rule.categories && rule.categories.length > 0) {
        return rule.categories.includes(f.category);
      }
      return true;
    });

    if (matchingFindings.length > 0) {
      const violation: PolicyViolation = {
        rule,
        findings: matchingFindings,
        message: rule.message || `${matchingFindings.length} ${rule.severity} finding(s) detected`,
      };

      if (rule.action === 'fail') {
        violations.push(violation);
      } else if (rule.action === 'warn') {
        warnings.push(violation);
      }
    }
  }

  const policy = config.policy;
  if (policy) {
    if (policy.max_critical !== undefined && result.summary.CRITICAL > policy.max_critical) {
      violations.push({
        rule: { severity: 'CRITICAL', action: 'fail', message: `Max critical findings exceeded (${policy.max_critical})` },
        findings: result.findings.filter(f => f.severity === 'CRITICAL'),
        message: `Critical findings (${result.summary.CRITICAL}) exceed limit (${policy.max_critical})`,
      });
    }
    if (policy.max_high !== undefined && result.summary.HIGH > policy.max_high) {
      violations.push({
        rule: { severity: 'HIGH', action: 'fail', message: `Max high findings exceeded (${policy.max_high})` },
        findings: result.findings.filter(f => f.severity === 'HIGH'),
        message: `High findings (${result.summary.HIGH}) exceed limit (${policy.max_high})`,
      });
    }
  }

  return {
    passed: violations.length === 0,
    violations,
    warnings,
  };
}

export function formatPolicyEvaluation(evaluation: PolicyEvaluation): string {
  const lines: string[] = [];

  if (evaluation.passed) {
    lines.push('✓ Security policy: PASSED');
  } else {
    lines.push('✗ Security policy: FAILED');
  }

  if (evaluation.violations.length > 0) {
    lines.push('');
    lines.push('VIOLATIONS:');
    for (const v of evaluation.violations) {
      lines.push(`  FAIL ${v.rule.severity}: ${v.message}`);
    }
  }

  if (evaluation.warnings.length > 0) {
    lines.push('');
    lines.push('WARNINGS:');
    for (const w of evaluation.warnings) {
      lines.push(`  WARN ${w.rule.severity}: ${w.message}`);
    }
  }

  return lines.join('\n');
}
