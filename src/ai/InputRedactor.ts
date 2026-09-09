const SECRET_PATTERN = /(sk[-_][A-Za-z0-9_]{16,}|pk[-_][A-Za-z0-9_]{16,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{20,}|eyJ[A-Za-z0-9_-]{8,})\S*/g;

export function redactInput(text: string, knownSecrets: string[] = []): string {
  let out = text;

  for (const secret of knownSecrets) {
    if (secret && secret.length >= 6) {
      out = out.split(secret).join('[REDACTED]');
    }
  }

  out = out.replace(SECRET_PATTERN, '[REDACTED]');
  return out;
}