import { Finding, Severity, Confidence } from '../models/Finding';
import { AIConfig, PrivacyConfig } from './types';
import { LLMClient, ChatMessage } from './LLMClient';
import { redactInput } from './InputRedactor';

export interface CorrelatorResult {
  text: string;
  provider: string;
  model: string;
}

const MAX_FINDINGS_IN_PROMPT = 60;

export class LLMCorrelator {
  constructor(private config: AIConfig, private privacy: PrivacyConfig, private client?: LLMClient) {}

  async correlate(
    findings: Finding[],
    technologies: string[],
    attackSurfaces: string[]
  ): Promise<CorrelatorResult | null> {
    if (!this.config.enabled || this.config.provider === 'disabled') {
      return null;
    }

    try {
      const client = this.client || new LLMClient(this.config);
      const prompt = this.buildPrompt(findings, technologies, attackSurfaces);
      const text = await client.chat([
        { role: 'system', content: this.systemPrompt() },
        { role: 'user', content: prompt },
      ]);
      return {
        text,
        provider: this.config.provider || 'unknown',
        model: this.clientModel(),
      };
    } catch {
      return null;
    }
  }

  private clientModel(): string {
    const defaults: Record<string, string> = {
      openai: 'gpt-4o-mini',
      anthropic: 'claude-3-5-haiku-latest',
      'openai-compatible': this.config.model || 'hosted model',
      ollama: this.config.model || 'llama3.1',
    };
    return this.config.model
      || (this.config.provider ? defaults[this.config.provider] : undefined)
      || 'unknown';
  }

  private systemPrompt(): string {
    return [
      'You are Lui, an expert application security analyst embedded in a CLI security auditor.',
      'You receive only machine-reported findings. Your job is to help the developer act on them.',
      'Rules:',
      '- Only discuss the exact findings provided. Never invent or imply vulnerabilities that were not reported.',
      '- Never include actual secret material; if you see [REDACTED], refer to it as a redacted secret.',
      '- Be concise, practical, and specific. Prefer short actionable bullet lists.',
      '- Prioritize by severity and exploitability.',
    ].join('\n');
  }

  private buildPrompt(findings: Finding[], technologies: string[], attackSurfaces: string[]): string {
    const counts = this.severityCounts(findings);
    const lines: string[] = [];
    const top = findings.slice(0, MAX_FINDINGS_IN_PROMPT);

    lines.push(`Scan summary: ${findings.length} findings.`);
    lines.push(`Severity breakdown: critical=${counts.CRITICAL}, high=${counts.HIGH}, medium=${counts.MEDIUM}, low=${counts.LOW}, info=${counts.INFO}`);
    lines.push(`Technologies: ${technologies.join(', ') || 'unknown'}`);
    lines.push(`Attack surfaces: ${attackSurfaces.join(', ') || 'none detected'}`);
    lines.push('');

    if (top.length === 0) {
      lines.push('No security findings were detected in this scan.');
    } else {
      lines.push('Findings:');
      for (const f of top) {
        const loc = f.affectedFiles[0];
        const location = loc ? `${loc.file}${loc.line ? `:${loc.line}` : ''}` : 'unknown';
        const evidence = this.privacy.send_source_to_ai
          ? this.redact(f.evidence.join(' | '))
          : this.redact(f.evidence.slice(0, 2).join(' | '));
        lines.push(`- [${f.id}] ${f.severity}/${f.confidence} ${f.title} @ ${location}`);
        if (evidence) lines.push(`  evidence: ${evidence}`);
      }
    }

    lines.push('');
    lines.push('Please produce:');
    lines.push('1. A prioritized remediation plan (highest impact first).');
    lines.push('2. Root-cause analysis of the most critical findings.');
    lines.push('3. Any meaningful correlations between findings that indicate an attack chain.');
    lines.push('4. Concrete verification steps a developer can run locally.');
    return lines.join('\n');
  }

  private severityCounts(findings: Finding[]): Record<Severity, number> {
    const counts: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    for (const f of findings) counts[f.severity]++;
    return counts;
  }

  private redact(text: string): string {
    if (!this.privacy.redact_secrets) return text;
    return redactInput(text);
  }
}