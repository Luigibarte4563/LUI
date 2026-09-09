import { LLMCorrelator } from '../src/ai/LLMCorrelator';
import { LLMClient, ChatMessage } from '../src/ai/LLMClient';
import { redactInput } from '../src/ai/InputRedactor';
import { createFinding } from '../src/models/Finding';
import { ConfigLoader } from '../src/config/ConfigLoader';
import { ProjectDiscovery } from '../src/discovery/ProjectDiscovery';
import { SecurityAgent } from '../src/agent/SecurityAgent';
import * as path from 'path';

const FIXTURES_PATH = path.join(__dirname, 'fixtures', 'vulnerable-node');

describe('Input redaction', () => {
  test('masks known API key formats', () => {
    const redacted = redactInput('key FAKE_API_KEY_FOR_TESTING_12345 end');
    expect(redacted).not.toContain('FAKE_API_KEY_FOR_TESTING_12345');
    expect(redacted).toContain('[REDACTED]');
  });

  test('replaces known secrets by value', () => {
    const secret = 'super_secret_key_12345';
    const redacted = redactInput(`secret is ${secret} here`, [secret]);
    expect(redacted).not.toContain(secret);
    expect(redacted).toContain('[REDACTED]');
  });
});

describe('LLMCorrelator', () => {
  test('returns null when the provider is disabled', async () => {
    const correlator = new LLMCorrelator({ enabled: false, provider: 'disabled' }, {});
    const result = await correlator.correlate([], ['Node.js'], []);
    expect(result).toBeNull();
  });

  test('returns null when the provider is not enabled', async () => {
    const correlator = new LLMCorrelator({ provider: 'openai' }, {});
    const result = await correlator.correlate([], ['Node.js'], []);
    expect(result).toBeNull();
  });

  test('uses a mock client and never leaks secrets into the prompt', async () => {
    let captured: ChatMessage[] = [];

    const mockClient = {
      chat: async (messages: ChatMessage[]) => {
        captured = messages;
        return 'Prioritized remediation plan...';
      },
    } as unknown as LLMClient;

    const finding = createFinding({
      id: 'LUI-SEC-004',
      title: 'Potential secret: API key',
      severity: 'CRITICAL',
      category: 'Secrets',
      description: 'sk_test_hardcoded_secret_value',
      evidence: ['sk_test_hardcoded_secret_value', 'Key: sk_test_hardcoded_secret_value'],
      scanner: 'SecretScanner',
    });

    const correlator = new LLMCorrelator(
      { enabled: true, provider: 'openai', model: 'gpt-4o-mini' },
      { redact_secrets: true, send_source_to_ai: true },
      mockClient
    );

    const result = await correlator.correlate([finding], ['Node.js'], ['Backend API']);
    expect(result).not.toBeNull();
    expect(result!.text).toContain('Prioritized remediation plan');
    expect(result!.provider).toBe('openai');

    const userPrompt = captured.find(m => m.role === 'user')?.content || '';
    expect(userPrompt).toContain('LUI-SEC-004');
    expect(userPrompt).not.toContain('sk_test_hardcoded_secret_value');
    expect(userPrompt).toContain('[REDACTED]');
  });

  test('does not invent findings in the prompt summary', async () => {
    let captured: ChatMessage[] = [];
    const mockClient = {
      chat: async (messages: ChatMessage[]) => {
        captured = messages;
        return 'ok';
      },
    } as unknown as LLMClient;

    const correlator = new LLMCorrelator(
      { enabled: true, provider: 'openai' },
      {},
      mockClient
    );

    await correlator.correlate([], ['Node.js'], []);
    const userPrompt = captured.find(m => m.role === 'user')?.content || '';
    expect(userPrompt).toContain('No security findings were detected');
  });
});

describe('AI integration default behavior', () => {
  test('scan metadata records that AI analysis is disabled', async () => {
    const configLoader = new ConfigLoader(FIXTURES_PATH);
    const discovery = new ProjectDiscovery(FIXTURES_PATH, configLoader.getExcludes());
    const project = await discovery.discover();

    const agent = new SecurityAgent(project);
    const result = await agent.scan({ scanType: 'deep' });

    const aiAnalysis = result.metadata.aiAnalysis as { enabled: boolean };
    expect(aiAnalysis.enabled).toBe(false);
  });
});