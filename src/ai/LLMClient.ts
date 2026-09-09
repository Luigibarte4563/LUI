import * as http from 'http';
import * as https from 'https';
import { URL } from 'url';
import { AIConfig } from './types';

export interface ChatMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

const DEFAULT_MODELS: Record<string, string> = {
  openai: 'gpt-4o-mini',
  anthropic: 'claude-3-5-haiku-latest',
  'openai-compatible': 'gpt-4o-mini',
  ollama: 'llama3.1',
};

const REQUEST_TIMEOUT = 60000;

export class LLMClient {
  constructor(private config: AIConfig) {}

  async chat(messages: ChatMessage[]): Promise<string> {
    const provider = this.config.provider;

    switch (provider) {
      case 'disabled':
        throw new Error('AI provider is disabled');
      case 'openai':
        return this.chatOpenAICompatible(messages);
      case 'openai-compatible':
        return this.chatOpenAICompatible(messages);
      case 'anthropic':
        return this.chatAnthropic(messages);
      case 'ollama':
        return this.chatOllama(messages);
      default:
        throw new Error(`Unsupported AI provider: ${provider}`);
    }
  }

  private model(): string {
    return this.config.model
      || (this.config.provider ? DEFAULT_MODELS[this.config.provider] : undefined)
      || 'gpt-4o-mini';
  }

  private async chatOpenAICompatible(messages: ChatMessage[]): Promise<string> {
    if (!this.config.apiKey) {
      throw new Error('AI provider requires an apiKey in .lui.yml');
    }
    const base = (this.config.baseUrl || 'https://api.openai.com/v1').replace(/\/$/, '');
    const url = `${base}/chat/completions`;
    const body = {
      model: this.model(),
      messages,
      max_tokens: 1200,
      temperature: 0.2,
    };
    const response = await this.postJson(url, {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${this.config.apiKey}`,
    }, body);
    const data = JSON.parse(response);
    const content = data?.choices?.[0]?.message?.content;
    if (!content) throw new Error('AI provider returned an empty response');
    return String(content).trim();
  }

  private async chatAnthropic(messages: ChatMessage[]): Promise<string> {
    if (!this.config.apiKey) {
      throw new Error('AI provider requires an apiKey in .lui.yml');
    }
    const base = (this.config.baseUrl || 'https://api.anthropic.com').replace(/\/$/, '');
    const url = `${base}/v1/messages`;
    const body = {
      model: this.model(),
      max_tokens: 1200,
      messages: messages.map(m => ({ role: m.role === 'system' ? 'user' : m.role, content: m.content })),
    };
    const response = await this.postJson(url, {
      'Content-Type': 'application/json',
      'x-api-key': this.config.apiKey,
      'anthropic-version': '2023-06-01',
    }, body);
    const data = JSON.parse(response);
    const content = data?.content?.[0]?.text;
    if (!content) throw new Error('AI provider returned an empty response');
    return String(content).trim();
  }

  private async chatOllama(messages: ChatMessage[]): Promise<string> {
    const base = (this.config.baseUrl || 'http://localhost:11434').replace(/\/$/, '');
    const url = `${base}/api/chat`;
    const body = {
      model: this.model(),
      messages,
      stream: false,
    };
    const response = await this.postJson(url, { 'Content-Type': 'application/json' }, body);
    const data = JSON.parse(response);
    const content = data?.message?.content;
    if (!content) throw new Error('AI provider returned an empty response');
    return String(content).trim();
  }

  private postJson(url: string, headers: Record<string, string>, body: unknown): Promise<string> {
    return new Promise((resolve, reject) => {
      let target: URL;
      try {
        target = new URL(url);
      } catch {
        reject(new Error(`Invalid AI provider URL: ${url}`));
        return;
      }

      const lib = target.protocol === 'https:' ? https : http;
      const payload = JSON.stringify(body);
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);

      const request = lib.request(
        target,
        {
          method: 'POST',
          headers: { ...headers, 'Content-Length': Buffer.byteLength(payload) },
          signal: controller.signal,
        },
        (res) => {
          let data = '';
          res.setEncoding('utf8');
          res.on('data', (chunk: string) => { data += chunk; });
          res.on('end', () => {
            clearTimeout(timeout);
            if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
              resolve(data);
            } else {
              reject(new Error(`AI provider returned HTTP ${res.statusCode}: ${data.slice(0, 300)}`));
            }
          });
        }
      );

      request.on('error', (err) => {
        clearTimeout(timeout);
        reject(err);
      });

      request.write(payload);
      request.end();
    });
  }
}