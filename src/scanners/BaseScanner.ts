import { Finding } from '../models/Finding';
import { ProjectProfile } from '../models/ProjectProfile';
import { AIConfig, PrivacyConfig } from '../ai/types';

export interface ScanContext {
  project: ProjectProfile;
  rootPath: string;
  scanType: 'quick' | 'standard' | 'deep';
  config: Record<string, unknown>;
  fileContents: Map<string, string>;
  url?: string;
  ai?: AIConfig;
  privacy?: PrivacyConfig;
}

export interface Scanner {
  name: string;
  category: string;
  description: string;
  scan(context: ScanContext): Promise<Finding[]>;
  supported?(context: ScanContext): boolean;
}

export abstract class BaseScanner implements Scanner {
  name: string;
  category: string;
  description: string;

  constructor(name: string, category: string, description: string) {
    this.name = name;
    this.category = category;
    this.description = description;
  }

  abstract scan(context: ScanContext): Promise<Finding[]>;

  supported(context: ScanContext): boolean {
    return true;
  }

  protected getFileContent(context: ScanContext, filePath: string): string | null {
    if (context.fileContents.has(filePath)) {
      return context.fileContents.get(filePath)!;
    }
    try {
      const fs = require('fs');
      const content = fs.readFileSync(filePath, 'utf-8');
      context.fileContents.set(filePath, content);
      return content;
    } catch {
      return null;
    }
  }

  protected getLineNumber(content: string, substring: string, startIndex: number = 0): number {
    const index = content.toLowerCase().indexOf(substring.toLowerCase(), startIndex);
    if (index === -1) return 0;
    return content.substring(0, index).split('\n').length;
  }

  // Skip Lui's own implementation source so a self-scan does not flag the scanner internals.
  protected isSelfSource(relPath: string): boolean {
    const p = relPath.replace(/\\/g, '/');
    return /^(?:src\/(?:scanners|utils|analysis|reporters|discovery|agent|config|models|knowledge|ai|remediation)\/|src\/(?:cli|index)\.)/.test(p);
  }
}
