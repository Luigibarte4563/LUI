import * as fs from 'fs';
import * as path from 'path';
import { z } from 'zod';

const LuiConfigSchema = z.object({
  project: z.object({
    name: z.string().optional(),
  }).optional(),
  scan: z.object({
    depth: z.enum(['quick', 'standard', 'deep']).optional(),
  }).optional(),
  exclude: z.array(z.string()).optional(),
  security: z.object({
    secrets: z.boolean().optional(),
    dependencies: z.boolean().optional(),
    sast: z.boolean().optional(),
    auth: z.boolean().optional(),
    authorization: z.boolean().optional(),
    api: z.boolean().optional(),
    docker: z.boolean().optional(),
    cicd: z.boolean().optional(),
    dynamic_cve: z.boolean().optional(),
  }).optional(),
  ai: z.object({
    enabled: z.boolean().optional(),
    provider: z.enum(['openai', 'anthropic', 'ollama', 'openai-compatible', 'disabled']).optional(),
    model: z.string().optional(),
    apiKey: z.string().optional(),
    baseUrl: z.string().optional(),
  }).optional(),
  privacy: z.object({
    local_only: z.boolean().optional(),
    redact_secrets: z.boolean().optional(),
    send_source_to_ai: z.boolean().optional(),
  }).optional(),
  policy: z.object({
    fail_on: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional(),
  }).optional(),
});

export type LuiConfig = z.infer<typeof LuiConfigSchema>;

const DEFAULT_CONFIG: LuiConfig = {
  scan: { depth: 'standard' },
  exclude: ['node_modules', 'vendor', 'dist', 'build', '.git', '__pycache__', 'coverage', '.next', '.nuxt', 'venv', 'target', 'bin', 'obj'],
  security: {
    secrets: true,
    dependencies: true,
    sast: true,
    auth: true,
    authorization: true,
    api: true,
    docker: true,
    cicd: true,
    dynamic_cve: false,
  },
  ai: { enabled: false, provider: 'disabled' },
  privacy: { local_only: true, redact_secrets: true, send_source_to_ai: false },
  policy: { fail_on: 'high' },
};

export class ConfigLoader {
  private config: LuiConfig;

  constructor(projectPath: string) {
    this.config = this.loadConfig(projectPath);
  }

  private loadConfig(projectPath: string): LuiConfig {
    const candidates = ['.lui.yml', '.lui.yaml', '.lui.json', 'lui.config.js'];
    for (const file of candidates) {
      const configPath = path.join(projectPath, file);
      if (fs.existsSync(configPath)) {
        try {
          const content = fs.readFileSync(configPath, 'utf-8');
          let parsed: unknown;
          if (file.endsWith('.json')) {
            parsed = JSON.parse(content);
          } else if (file.endsWith('.js')) {
            parsed = require(configPath);
          } else {
            const yaml = require('yaml');
            parsed = yaml.parse(content);
          }
          const result = LuiConfigSchema.safeParse(parsed);
          if (result.success) {
            return this.mergeConfigs(DEFAULT_CONFIG, result.data);
          }
        } catch {
          // ignore config errors
        }
      }
    }
    return { ...DEFAULT_CONFIG };
  }

  private mergeConfigs(base: LuiConfig, override: LuiConfig): LuiConfig {
    const merged = { ...base };
    if (override.project) merged.project = override.project;
    if (override.scan) merged.scan = { ...merged.scan, ...override.scan };
    if (override.exclude) merged.exclude = override.exclude;
    if (override.security) merged.security = { ...merged.security, ...override.security };
    if (override.ai) merged.ai = { ...merged.ai, ...override.ai };
    if (override.privacy) merged.privacy = { ...merged.privacy, ...override.privacy };
    if (override.policy) merged.policy = { ...merged.policy, ...override.policy };
    return merged;
  }

  getConfig(): LuiConfig {
    return this.config;
  }

  getExcludes(): string[] {
    return this.config.exclude || DEFAULT_CONFIG.exclude!;
  }

  isSecurityEnabled(category: string): boolean {
    const sec = this.config.security || {};
    if (category in sec) {
      return (sec as Record<string, boolean>)[category] !== false;
    }
    return true;
  }
}
