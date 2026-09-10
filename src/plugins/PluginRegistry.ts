import { Scanner, ScanContext } from '../scanners/BaseScanner';
import { Finding } from '../models/Finding';

export interface LuiPlugin {
  name: string;
  version: string;
  description: string;
  author?: string;
  scanners?: Scanner[];
  hooks?: PluginHooks;
}

export interface PluginHooks {
  beforeScan?: (context: ScanContext) => Promise<void> | void;
  afterScan?: (findings: Finding[], context: ScanContext) => Promise<Finding[]> | Finding[];
  onFinding?: (finding: Finding) => Promise<Finding | null> | Finding | null;
  onReport?: (result: unknown) => Promise<unknown> | unknown;
}

export class PluginRegistry {
  private plugins: LuiPlugin[] = [];

  register(plugin: LuiPlugin): void {
    if (this.plugins.some(p => p.name === plugin.name)) {
      throw new Error(`Plugin "${plugin.name}" is already registered`);
    }
    this.plugins.push(plugin);
  }

  unregister(name: string): void {
    this.plugins = this.plugins.filter(p => p.name !== name);
  }

  getPlugin(name: string): LuiPlugin | undefined {
    return this.plugins.find(p => p.name === name);
  }

  getAllPlugins(): LuiPlugin[] {
    return [...this.plugins];
  }

  getScanners(): Scanner[] {
    const scanners: Scanner[] = [];
    for (const plugin of this.plugins) {
      if (plugin.scanners) {
        scanners.push(...plugin.scanners);
      }
    }
    return scanners;
  }

  async runBeforeScanHooks(context: ScanContext): Promise<void> {
    for (const plugin of this.plugins) {
      if (plugin.hooks?.beforeScan) {
        await plugin.hooks.beforeScan(context);
      }
    }
  }

  async runAfterScanHooks(findings: Finding[], context: ScanContext): Promise<Finding[]> {
    let result = [...findings];
    for (const plugin of this.plugins) {
      if (plugin.hooks?.afterScan) {
        result = await plugin.hooks.afterScan(result, context);
      }
    }
    return result;
  }

  async runOnFindingHooks(finding: Finding): Promise<Finding | null> {
    let current: Finding | null = finding;
    for (const plugin of this.plugins) {
      if (current && plugin.hooks?.onFinding) {
        current = await plugin.hooks.onFinding(current);
      }
    }
    return current;
  }

  async runOnReportHooks<T>(result: T): Promise<T> {
    let current: T = result;
    for (const plugin of this.plugins) {
      if (plugin.hooks?.onReport) {
        current = (await plugin.hooks.onReport(current)) as T;
      }
    }
    return current;
  }
}

export function createPlugin(config: {
  name: string;
  version: string;
  description: string;
  author?: string;
  scanners?: Scanner[];
  hooks?: PluginHooks;
}): LuiPlugin {
  return {
    name: config.name,
    version: config.version,
    description: config.description,
    author: config.author,
    scanners: config.scanners,
    hooks: config.hooks,
  };
}
