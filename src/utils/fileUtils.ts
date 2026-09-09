import * as fs from 'fs';
import * as path from 'path';

export function readFileSafe(filePath: string): string | null {
  try {
    return fs.readFileSync(filePath, 'utf-8');
  } catch {
    return null;
  }
}

export function fileExists(filePath: string): boolean {
  try {
    return fs.existsSync(filePath);
  } catch {
    return false;
  }
}

export function maskSecret(value: string): string {
  if (value.length <= 8) {
    return '*'.repeat(value.length);
  }
  const show = Math.min(4, Math.floor(value.length / 4));
  return value.substring(0, show) + '*'.repeat(value.length - show * 2) + value.substring(value.length - show);
}

export function relativePath(filePath: string, basePath: string): string {
  const rel = path.relative(basePath, filePath);
  return rel.replace(/\\/g, '/');
}

export function getAllFiles(dir: string, extensions?: string[], excludes?: string[]): string[] {
  const baseDir = dir;
  const excludeSet = new Set(excludes || []);

  const walk = (currentDir: string): string[] => {
    const results: string[] = [];
    try {
      const entries = fs.readdirSync(currentDir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = path.join(currentDir, entry.name);
        const rel = path.relative(baseDir, fullPath).replace(/\\/g, '/');
        if (excludeSet.has(entry.name)) continue;
        if (excludeSet.has(fullPath)) continue;
        if (excludeSet.has(rel)) continue;
        if ([...excludeSet].some(e => rel.startsWith(e + '/'))) continue;

        if (entry.isDirectory()) {
          results.push(...walk(fullPath));
        } else if (entry.isFile()) {
          if (!extensions || extensions.length === 0 || extensions.some(ext => entry.name.endsWith(ext))) {
            results.push(fullPath);
          }
        }
      }
    } catch {
      // Permission denied or other errors
    }
    return results;
  };

  return walk(dir);
}

export function countLines(content: string, offset?: number): number {
  if (offset === undefined) return content.split('\n').length;
  const lines = content.substring(0, offset).split('\n');
  return lines.length;
}

export function getLineAt(content: string, lineNumber: number): string {
  const lines = content.split('\n');
  if (lineNumber >= 1 && lineNumber <= lines.length) {
    return lines[lineNumber - 1];
  }
  return '';
}

export function getSnippetAt(content: string, lineNumber: number, context: number = 2): string {
  const lines = content.split('\n');
  const start = Math.max(0, lineNumber - 1 - context);
  const end = Math.min(lines.length, lineNumber + context);
  const result: string[] = [];
  for (let i = start; i < end; i++) {
    const marker = i === lineNumber - 1 ? '=>' : '  ';
    result.push(`${marker} ${i + 1}: ${lines[i]}`);
  }
  return result.join('\n');
}
