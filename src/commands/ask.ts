import chalk from 'chalk';
import { ScanResult } from '../models/ScanResult';
import { Finding, Severity } from '../models/Finding';
import { AIConfig, PrivacyConfig } from '../ai/types';
import { LLMClient } from '../ai/LLMClient';

export interface AskResponse {
  question: string;
  answer: string;
  suggestions: string[];
  dynamic?: boolean;
}

const SUGGESTED_QUESTIONS = [
  'Why is my security score low?',
  'What should I fix first?',
  'Show me critical findings',
  'Give me a summary',
  'How do I fix my SQL injection?',
  'Explain my weakest security area',
];

export async function askLuiDynamic(
  question: string,
  result: ScanResult | null,
  ai?: AIConfig,
  privacy?: PrivacyConfig
): Promise<AskResponse> {
  // If AI is enabled, use the LLM for a dynamic contextual response
  if (ai?.enabled && ai.provider && ai.provider !== 'disabled') {
    try {
      const client = new LLMClient(ai);

      const context = result
        ? buildScanContext(result)
        : 'No scan results available. The user has not run a scan yet.';

      const prompt = [
        `You are Lui, a security assistant embedded in a CLI security auditor.`,
        ``,
        `Available scan context:`,
        context,
        ``,
        `The user asks: "${question}"`,
        ``,
        `Answer helpfully, concisely, and practically.`,
        `Base your answer on the scan context when available.`,
        `If no scan exists, guide the user to run "lui scan" first.`,
        `Never claim vulnerabilities that aren't in the scan results.`,
      ].join('\n');

      const answer = await client.chat([
        { role: 'system', content: 'You are Lui, an expert security assistant. Be concise, practical, and action-oriented.' },
        { role: 'user', content: prompt },
      ]);

      return {
        question,
        answer,
        suggestions: SUGGESTED_QUESTIONS.slice(0, 3),
        dynamic: true,
      };
    } catch {
      // Fall through to rule-based if LLM fails
    }
  }

  return askLui(question, result);
}

function buildScanContext(result: ScanResult): string {
  const lines = [
    `Security Score: ${result.score}/100 (${result.scoreLabel})`,
    `Findings: ${result.findings.length} total`,
    `  CRITICAL: ${result.summary.CRITICAL}`,
    `  HIGH: ${result.summary.HIGH}`,
    `  MEDIUM: ${result.summary.MEDIUM}`,
    `  LOW: ${result.summary.LOW}`,
    `  INFO: ${result.summary.INFO}`,
    `Technologies: ${[...(result.technologyProfile?.languages || []), ...(result.technologyProfile?.frameworks || [])].join(', ') || 'unknown'}`,
    ``,
    `Top findings:`,
  ];

  const top = result.findings
    .filter(f => f.status !== 'suppressed')
    .sort((a, b) => {
      const order: Record<Severity, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
      return order[a.severity] - order[b.severity];
    })
    .slice(0, 10);

  for (const f of top) {
    const loc = f.affectedFiles[0];
    const location = loc ? `${loc.file}${loc.line ? `:${loc.line}` : ''}` : 'unknown';
    lines.push(`- [${f.id}] ${f.severity}/${f.confidence} ${f.title} @ ${location}`);
  }

  return lines.join('\n');
}

export function askLui(question: string, result: ScanResult | null): AskResponse {
  const q = question.toLowerCase();

  if (q.includes('score') || q.includes('why low') || q.includes('why is')) {
    return explainScore(result);
  }

  if (q.includes('first') || q.includes('fix first') || q.includes('priority') || q.includes('what should')) {
    return prioritizeFixes(result);
  }

  if (q.includes('critical') || q.includes('worst')) {
    return showCritical(result);
  }

  if (q.includes('summary') || q.includes('overview')) {
    return showSummary(result);
  }

  if (q.includes('sql') || q.includes('injection')) {
    return showInjectionGuidance(result);
  }

  if (q.includes('auth') || q.includes('login')) {
    return showAuthGuidance(result);
  }

  if (q.includes('secret') || q.includes('credential') || q.includes('password')) {
    return showSecretGuidance(result);
  }

  if (q.includes('dependenc') || q.includes('package') || q.includes('cve')) {
    return showDependencyGuidance(result);
  }

  if (q.includes('help') || q.includes('how')) {
    return showHelp();
  }

  return {
    question,
    answer: `I can help you understand your security posture. Try asking:\n- "Why is my security score low?"\n- "What should I fix first?"\n- "Show me critical findings"\n- "Give me a summary"`,
    suggestions: SUGGESTED_QUESTIONS.slice(0, 3),
  };
}

function explainScore(result: ScanResult | null): AskResponse {
  if (!result) {
    return {
      question: 'Why is my security score low?',
      answer: 'No scan results found. Run "lui scan" first.',
      suggestions: ['Run lui scan'],
    };
  }

  const reasons: string[] = [];

  if (result.summary.CRITICAL > 0) {
    reasons.push(`${result.summary.CRITICAL} CRITICAL finding(s)`);
  }
  if (result.summary.HIGH > 0) {
    reasons.push(`${result.summary.HIGH} HIGH finding(s)`);
  }
  if (result.summary.MEDIUM > 0) {
    reasons.push(`${result.summary.MEDIUM} MEDIUM finding(s)`);
  }

  const secretFindings = result.findings.filter(f => f.category === 'Secrets');
  if (secretFindings.length > 0) {
    reasons.push(`${secretFindings.length} exposed credential(s)`);
  }

  const answer = reasons.length > 0
    ? `Your score is ${result.score} primarily because of:\n${reasons.map((r, i) => `${i + 1}. ${r}`).join('\n')}`
    : `Your score is ${result.score}. No major issues detected.`;

  const topFinding = result.findings
    .filter(f => f.status !== 'suppressed')
    .sort((a, b) => {
      const order: Record<Severity, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
      return order[a.severity] - order[b.severity];
    })[0];

  const suggestions = topFinding
    ? [`Fix ${topFinding.id} first`, 'Review exposed credentials']
    : ['Run lui scan for latest results'];

  return { question: 'Why is my security score low?', answer, suggestions };
}

function prioritizeFixes(result: ScanResult | null): AskResponse {
  if (!result || result.findings.length === 0) {
    return {
      question: 'What should I fix first?',
      answer: 'No findings to prioritize.',
      suggestions: [],
    };
  }

  const sorted = result.findings
    .filter(f => f.status !== 'suppressed')
    .sort((a, b) => {
      const order: Record<Severity, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
      return order[a.severity] - order[b.severity];
    })
    .slice(0, 5);

  const lines = sorted.map((f, i) => `${i + 1}. [${f.severity}] ${f.title} (${f.id})`);

  return {
    question: 'What should I fix first?',
    answer: `Fix these in order:\n${lines.join('\n')}`,
    suggestions: sorted.map(f => `lui explain ${f.id}`),
  };
}

function showCritical(result: ScanResult | null): AskResponse {
  if (!result) {
    return { question: 'Show critical findings', answer: 'No scan results found.', suggestions: [] };
  }

  const critical = result.findings.filter(f => f.severity === 'CRITICAL' && f.status !== 'suppressed');
  if (critical.length === 0) {
    return {
      question: 'Show critical findings',
      answer: 'No critical findings detected.',
      suggestions: ['Check high-severity findings with "lui scan"'],
    };
  }

  const lines = critical.map(f => `- ${f.id}: ${f.title}\n  ${f.affectedFiles[0]?.file || 'Unknown'}:${f.affectedFiles[0]?.line || '?'}`);
  return {
    question: 'Show critical findings',
    answer: `${critical.length} critical finding(s):\n${lines.join('\n')}`,
    suggestions: critical.map(f => `lui explain ${f.id}`),
  };
}

function showSummary(result: ScanResult | null): AskResponse {
  if (!result) {
    return { question: 'Give me a summary', answer: 'No scan results found.', suggestions: [] };
  }

  const answer = [
    `Security Score: ${result.score}/100 (${result.scoreLabel})`,
    `Findings: ${result.findings.length} total`,
    `  CRITICAL: ${result.summary.CRITICAL}`,
    `  HIGH: ${result.summary.HIGH}`,
    `  MEDIUM: ${result.summary.MEDIUM}`,
    `  LOW: ${result.summary.LOW}`,
    `  INFO: ${result.summary.INFO}`,
    `Scan Type: ${result.scanType}`,
    `Target: ${result.target}`,
  ].join('\n');

  return { question: 'Give me a summary', answer, suggestions: ['What should I fix first?'] };
}

function showInjectionGuidance(result: ScanResult | null): AskResponse {
  const injection = result?.findings.filter(f =>
    f.category === 'Injection' || f.cwe === 'CWE-89' || f.cwe === 'CWE-79'
  ) || [];

  if (injection.length === 0) {
    return {
      question: 'How do I fix SQL injection?',
      answer: 'No injection findings detected in your latest scan.\nGeneral guidance: always use parameterized queries or prepared statements instead of string interpolation.',
      suggestions: ['Run lui scan to check for injection', 'What should I fix first?'],
    };
  }

  const lines = injection.slice(0, 5).map((f, i) => {
    const loc = f.affectedFiles[0];
    return `${i + 1}. ${f.title} (${f.id})${loc ? ` @ ${loc.file}:${loc.line}` : ''}\n   Fix: ${f.recommendation}`;
  });

  return {
    question: 'How do I fix SQL injection?',
    answer: `Found ${injection.length} injection finding(s):\n${lines.join('\n')}`,
    suggestions: injection.map(f => `lui explain ${f.id}`),
  };
}

function showAuthGuidance(result: ScanResult | null): AskResponse {
  const auth = result?.findings.filter(f =>
    f.category === 'Authentication' || f.category === 'Authorization'
  ) || [];

  if (auth.length === 0) {
    return {
      question: 'How is my authentication?',
      answer: 'No authentication or authorization findings detected in your latest scan.',
      suggestions: ['What should I fix first?'],
    };
  }

  const lines = auth.slice(0, 5).map((f, i) => {
    const loc = f.affectedFiles[0];
    return `${i + 1}. ${f.title} (${f.id})${loc ? ` @ ${loc.file}:${loc.line}` : ''}`;
  });

  return {
    question: 'How is my authentication?',
    answer: `Found ${auth.length} authentication/authorization issue(s):\n${lines.join('\n')}`,
    suggestions: auth.map(f => `lui explain ${f.id}`),
  };
}

function showSecretGuidance(result: ScanResult | null): AskResponse {
  const secrets = result?.findings.filter(f => f.category === 'Secrets') || [];

  if (secrets.length === 0) {
    return {
      question: 'Are my secrets safe?',
      answer: 'No exposed secrets or credentials detected in your latest scan.',
      suggestions: ['What should I fix first?'],
    };
  }

  const lines = secrets.slice(0, 5).map((f, i) => {
    const loc = f.affectedFiles[0];
    return `${i + 1}. ${f.title} (${f.id})${loc ? ` @ ${loc.file}:${loc.line}` : ''}\n   Action: Rotate the credential, remove it from source, and use a secret manager.`;
  });

  return {
    question: 'Are my secrets safe?',
    answer: `Found ${secrets.length} exposed secret(s). You should:\n1. Rotate/revoke each credential immediately\n2. Remove from source control\n3. Run "lui secrets history" to check if it was committed\n4. Move to environment variables or a secret manager\n\n${lines.join('\n')}`,
    suggestions: [...secrets.slice(0, 3).map(f => `lui fix ${f.id}`), 'lui secrets history'],
  };
}

function showDependencyGuidance(result: ScanResult | null): AskResponse {
  const deps = result?.findings.filter(f => f.category === 'Dependencies') || [];

  if (deps.length === 0) {
    return {
      question: 'Are my dependencies safe?',
      answer: 'No vulnerable dependencies detected in your latest scan.',
      suggestions: ['lui deps', 'What should I fix first?'],
    };
  }

  const lines = deps.slice(0, 5).map((f, i) => `${i + 1}. ${f.title} (${f.id})\n   Fix: ${f.recommendation}`);

  return {
    question: 'Are my dependencies safe?',
    answer: `Found ${deps.length} dependency issue(s):\n${lines.join('\n')}\n\nRun "lui deps" to see the full dependency graph.`,
    suggestions: ['lui deps', ...deps.slice(0, 3).map(f => `lui explain ${f.id}`)],
  };
}

function showHelp(): AskResponse {
  return {
    question: 'How can I use Lui?',
    answer: `Lui Security Assistant Commands:
- lui scan [path]       Scan a project
- lui explain <id>      Explain a finding
- lui fix <id>          Show remediation
- lui map               Attack surface map
- lui investigate       Security indicators
- lui verify <id>       Verify a fix
- lui deps              Dependency graph
- lui ask               Ask Lui questions
  
When AI is enabled in .lui.yml, "lui ask" provides dynamic contextual answers powered by your LLM provider.`,
    suggestions: ['Run lui scan', 'Show critical findings'],
  };
}

export function printAskResponse(response: AskResponse): void {
  console.log('');
  console.log(chalk.bold('  Lui Security Assistant'));
  console.log(chalk.gray('  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
  console.log('');
  console.log(`  ${chalk.gray('Q:')} ${response.question}`);
  console.log('');
  console.log(`  ${chalk.bold('A:')} ${response.answer}`);
  if (response.dynamic) {
    console.log('');
    console.log(chalk.cyan('  ✦ Dynamic response (LLM-powered)'));
  }
  console.log('');

  if (response.suggestions.length > 0) {
    console.log(chalk.gray('  Suggestions:'));
    for (const s of response.suggestions) {
      console.log(`    > ${s}`);
    }
    console.log('');
  }
}