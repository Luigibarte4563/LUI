import { Finding } from '../models/Finding';
import { AIConfig, PrivacyConfig } from './types';
import { LLMClient, ChatMessage } from './LLMClient';
import { redactInput } from './InputRedactor';

export interface AnalysisResult {
  findingId: string;
  validated: boolean;
  confidenceAdjustment: 'upgrade' | 'downgrade' | 'unchanged';
  enrichedDescription: string;
  exploitScenario: string;
  remediationSteps: string[];
  falsePositiveReason?: string;
}

const ANALYSIS_BATCH_SIZE = 5;
const REQUEST_TIMEOUT = 30000;

export class LLMAnalyzer {
  private client: LLMClient;

  constructor(private config: AIConfig, private privacy: PrivacyConfig) {
    this.client = new LLMClient(config);
  }

  async analyzeFinding(finding: Finding, fileContent?: string): Promise<AnalysisResult | null> {
    if (!this.config.enabled || this.config.provider === 'disabled') return null;

    try {
      const prompt = this.buildFindingPrompt(finding, fileContent);
      const response = await this.client.chat([
        { role: 'system', content: this.systemPrompt() },
        { role: 'user', content: prompt },
      ]);
      return this.parseAnalysisResult(finding.id, response);
    } catch {
      return null;
    }
  }

  async analyzeFindings(findings: Finding[], getFileContent: (file: string) => string | null): Promise<Map<string, AnalysisResult>> {
    const results = new Map<string, AnalysisResult>();
    if (!this.config.enabled || this.config.provider === 'disabled') return results;

    const batches = this.chunk(findings, ANALYSIS_BATCH_SIZE);
    for (const batch of batches) {
      const batchResults = await Promise.all(
        batch.map(async (f) => {
          const loc = f.affectedFiles[0];
          const content = loc ? getFileContent(loc.file) || undefined : undefined;
          const result = await this.analyzeFinding(f, content);
          return { id: f.id, result };
        })
      );
      for (const { id, result } of batchResults) {
        if (result) results.set(id, result);
      }
    }
    return results;
  }

  async validateSecret(matchedValue: string, contextLine: string, filePath: string): Promise<{ isReal: boolean; reason: string }> {
    if (!this.config.enabled || this.config.provider === 'disabled') {
      return { isReal: true, reason: 'AI validation disabled, assuming real' };
    }

    try {
      const prompt = [
        `You are a security analyst validating a potential secret detection.`,
        ``,
        `Matched value: ${this.redact(matchedValue)}`,
        `Context line: ${this.redact(contextLine)}`,
        `File: ${filePath}`,
        ``,
        `Determine if this is a REAL secret/credential or a false positive.`,
        `Consider:`,
        `- Is it a placeholder (xxx, CHANGE_ME, example, test)?`,
        `- Is it in a test file or documentation?`,
        `- Is it a truncated or partial value?`,
        `- Does the context suggest it's a real credential?`,
        ``,
        `Respond with ONLY a JSON object:`,
        `{"isReal": true/false, "reason": "brief explanation"}`,
      ].join('\n');

      const response = await this.client.chat([
        { role: 'system', content: 'You are a security validation assistant. Respond only with JSON.' },
        { role: 'user', content: prompt },
      ]);

      const parsed = JSON.parse(response.trim());
      return { isReal: parsed.isReal, reason: parsed.reason };
    } catch {
      return { isReal: true, reason: 'Validation failed, assuming real' };
    }
  }

  async explainFinding(finding: Finding, dataFlowSteps?: string[]): Promise<string> {
    if (!this.config.enabled || this.config.provider === 'disabled') {
      return finding.description;
    }

    try {
      const flowContext = dataFlowSteps?.length
        ? `\nData flow: ${dataFlowSteps.join(' → ')}`
        : '';

      const prompt = [
        `Explain this security finding to a developer in 2-3 sentences:`,
        ``,
        `Finding: ${finding.title}`,
        `Severity: ${finding.severity}`,
        `Category: ${finding.category}`,
        `CWE: ${finding.cwe}`,
        `Description: ${finding.description}`,
        `Impact: ${finding.impact}`,
        flowContext,
        ``,
        `Be specific about why this is dangerous and how it could be exploited.`,
        `Use plain language, not security jargon.`,
      ].join('\n');

      return await this.client.chat([
        { role: 'system', content: 'You are a helpful security mentor explaining vulnerabilities to developers.' },
        { role: 'user', content: prompt },
      ]);
    } catch {
      return finding.description;
    }
  }

  async suggestFix(finding: Finding, fileContent?: string): Promise<string> {
    if (!this.config.enabled || this.config.provider === 'disabled') {
      return finding.recommendation;
    }

    try {
      const codeContext = fileContent
        ? `\nCurrent code:\n\`\`\`\n${this.redact(fileContent.slice(0, 2000))}\n\`\`\``
        : '';

      const prompt = [
        `Suggest a specific code fix for this security vulnerability:`,
        ``,
        `Vulnerability: ${finding.title}`,
        `Category: ${finding.category}`,
        `Current recommendation: ${finding.recommendation}`,
        codeContext,
        ``,
        `Provide:`,
        `1. The specific code change needed`,
        `2. Why this fix works`,
        `3. Any trade-offs or considerations`,
        ``,
        `Use the same programming language as the source code.`,
      ].join('\n');

      return await this.client.chat([
        { role: 'system', content: 'You are a senior security engineer suggesting code fixes. Be specific and practical.' },
        { role: 'user', content: prompt },
      ]);
    } catch {
      return finding.recommendation;
    }
  }

  private systemPrompt(): string {
    return [
      'You are Lui, an expert application security analyst.',
      'You analyze security findings to validate them and provide actionable guidance.',
      'Rules:',
      '- Only analyze the finding provided. Never invent new vulnerabilities.',
      '- Be specific about the risk and exploitation scenario.',
      '- Provide concrete, actionable remediation steps.',
      '- If a finding is likely a false positive, explain why.',
    ].join('\n');
  }

  private buildFindingPrompt(finding: Finding, fileContent?: string): string {
    const loc = finding.affectedFiles[0];
    const location = loc ? `${loc.file}:${loc.line || '?'}` : 'unknown';
    const evidence = this.redact(finding.evidence.join('\n'));

    const lines = [
      `Analyze this security finding:`,
      ``,
      `ID: ${finding.id}`,
      `Title: ${finding.title}`,
      `Severity: ${finding.severity}`,
      `Confidence: ${finding.confidence}`,
      `Category: ${finding.category}`,
      `CWE: ${finding.cwe}`,
      `Location: ${location}`,
      `Description: ${finding.description}`,
      `Impact: ${finding.impact}`,
      `Evidence: ${evidence}`,
    ];

    if (fileContent) {
      lines.push(``, `Source code context:`, '```', this.redact(fileContent.slice(0, 2000)), '```');
    }

    lines.push(
      '',
      'Provide a JSON analysis:',
      '{',
      '  "validated": true/false,',
      '  "confidenceAdjustment": "upgrade"|"downgrade"|"unchanged",',
      '  "enrichedDescription": "detailed explanation of the vulnerability",',
      '  "exploitScenario": "how an attacker could exploit this",',
      '  "remediationSteps": ["step1", "step2", ...]',
      '}'
    );

    return lines.join('\n');
  }

  private parseAnalysisResult(findingId: string, response: string): AnalysisResult | null {
    try {
      const jsonMatch = response.match(/\{[\s\S]*\}/);
      if (!jsonMatch) return null;

      const parsed = JSON.parse(jsonMatch[0]);
      return {
        findingId,
        validated: parsed.validated ?? true,
        confidenceAdjustment: parsed.confidenceAdjustment ?? 'unchanged',
        enrichedDescription: parsed.enrichedDescription ?? '',
        exploitScenario: parsed.exploitScenario ?? '',
        remediationSteps: Array.isArray(parsed.remediationSteps) ? parsed.remediationSteps : [],
        falsePositiveReason: parsed.falsePositiveReason,
      };
    } catch {
      return null;
    }
  }

  private chunk<T>(array: T[], size: number): T[][] {
    const chunks: T[][] = [];
    for (let i = 0; i < array.length; i += size) {
      chunks.push(array.slice(i, i + size));
    }
    return chunks;
  }

  private redact(text: string): string {
    if (!this.privacy.redact_secrets) return text;
    return redactInput(text);
  }
}
