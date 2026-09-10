import { Finding } from '../models/Finding';

export interface RotationGuidance {
  findingId: string;
  secretType: string;
  steps: RotationStep[];
  gitHistoryWarning: boolean;
  severity: string;
}

export interface RotationStep {
  order: number;
  action: string;
  command?: string;
}

export function generateRotationGuidance(finding: Finding): RotationGuidance | null {
  if (finding.category !== 'Secrets') return null;

  const secretType = detectSecretType(finding);
  const steps = buildRotationSteps(secretType, finding);

  return {
    findingId: finding.id,
    secretType,
    steps,
    gitHistoryWarning: true,
    severity: finding.severity,
  };
}

function detectSecretType(finding: Finding): string {
  const desc = finding.description.toLowerCase();
  const title = finding.title.toLowerCase();
  const combined = `${desc} ${title}`;

  if (combined.includes('aws') || combined.includes('akia')) return 'AWS Credential';
  if (combined.includes('stripe')) return 'Stripe API Key';
  if (combined.includes('github') || combined.includes('ghp_')) return 'GitHub Token';
  if (combined.includes('slack') || combined.includes('xox')) return 'Slack Token';
  if (combined.includes('private key') || combined.includes('ssh')) return 'Private Key';
  if (combined.includes('database') || combined.includes('db_') || combined.includes('mysql') || combined.includes('postgres')) return 'Database Credential';
  if (combined.includes('api_key') || combined.includes('apikey')) return 'API Key';
  if (combined.includes('password')) return 'Password';
  if (combined.includes('jwt') || combined.includes('token')) return 'Token';
  return 'Credential';
}

function buildRotationSteps(secretType: string, finding: Finding): RotationStep[] {
  const steps: RotationStep[] = [
    { order: 1, action: `Revoke/rotate the exposed ${secretType}` },
    { order: 2, action: `Remove the ${secretType} from source code` },
    { order: 3, action: 'Check git history for previous commits containing the secret' },
    { order: 4, action: 'Check CI/CD logs for exposed secrets', command: 'lui secrets history' },
    { order: 5, action: 'Check deployment environments for the exposed credential' },
    { order: 6, action: 'Replace with a secret management solution', command: '# Consider using environment variables or a vault service' },
  ];

  if (secretType.includes('AWS')) {
    steps.splice(3, 0, {
      order: 4,
      action: 'Check AWS CloudTrail for unauthorized access',
      command: 'aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<KEY_ID>',
    });
  }

  if (secretType.includes('Database')) {
    steps.splice(3, 0, {
      order: 4,
      action: 'Check database access logs for unauthorized connections',
    });
  }

  return steps;
}

export function formatRotationGuidance(guidance: RotationGuidance): string {
  const lines: string[] = [];
  lines.push(`Recommended response for ${guidance.findingId}:`);
  lines.push('');
  lines.push(`Secret type: ${guidance.secretType}`);
  lines.push('');

  for (const step of guidance.steps) {
    lines.push(`${step.order}. ${step.action}`);
    if (step.command) {
      lines.push(`   Command: ${step.command}`);
    }
  }

  if (guidance.gitHistoryWarning) {
    lines.push('');
    lines.push('⚠  This credential may have been committed previously.');
    lines.push('Run: lui secrets history');
  }

  return lines.join('\n');
}
