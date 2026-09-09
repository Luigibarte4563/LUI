export interface AIConfig {
  enabled?: boolean;
  provider?: 'openai' | 'anthropic' | 'ollama' | 'openai-compatible' | 'disabled';
  model?: string;
  apiKey?: string;
  baseUrl?: string;
}

export interface PrivacyConfig {
  local_only?: boolean;
  redact_secrets?: boolean;
  send_source_to_ai?: boolean;
}