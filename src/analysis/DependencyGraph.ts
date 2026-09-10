import * as fs from 'fs';
import * as path from 'path';
import { Finding } from '../models/Finding';

export interface DependencyNode {
  name: string;
  version: string;
  type: 'direct' | 'transitive';
  category: string;
  vulnerabilities: string[];
  children: DependencyEdge[];
}

export interface DependencyEdge {
  from: string;
  to: string;
  type: 'depends_on' | 'optional' | 'peer';
}

export interface DependencyGraph {
  roots: DependencyNode[];
  allNodes: Map<string, DependencyNode>;
  vulnerablePaths: VulnerablePath[];
}

export interface VulnerablePath {
  path: string[];
  findingId: string;
  severity: string;
}

export function buildDependencyGraph(
  rootPath: string,
  findings: Finding[]
): DependencyGraph {
  const allNodes = new Map<string, DependencyNode>();
  const roots: DependencyNode[] = [];

  const pkgPath = path.join(rootPath, 'package.json');
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };

      for (const [name, version] of Object.entries(deps || {})) {
        const node = buildNode(name, version as string, 'direct', findings);
        roots.push(node);
        allNodes.set(name, node);
      }
    } catch { /* ignore */ }
  }

  const vulnerablePaths = findVulnerablePaths(roots, findings);

  return { roots, allNodes, vulnerablePaths };
}

function buildNode(
  name: string,
  version: string,
  type: 'direct' | 'transitive',
  findings: Finding[]
): DependencyNode {
  const depFindings = findings.filter(f =>
    f.category === 'Dependencies' &&
    f.title.toLowerCase().includes(name.toLowerCase())
  );

  const category = detectCategory(name);

  return {
    name,
    version: version.replace(/[\^~>=<]/g, ''),
    type,
    category,
    vulnerabilities: depFindings.map(f => f.id),
    children: [],
  };
}

function detectCategory(name: string): string {
  const categories: Record<string, string[]> = {
    'Web Framework': ['express', 'fastify', 'koa', 'nest', 'hapi', 'django', 'flask', 'fastapi', 'laravel', 'rails'],
    'Frontend': ['react', 'vue', 'angular', 'svelte', 'next', 'nuxt', 'gatsby'],
    'Database': ['mysql', 'pg', 'mongoose', 'sqlite', 'redis', 'sequelize', 'typeorm', 'prisma', 'knex'],
    'Auth': ['jsonwebtoken', 'bcrypt', 'passport', 'oauth', 'jwt-decode', 'jose'],
    'HTTP Client': ['axios', 'node-fetch', 'got', 'request', 'superagent', 'undici'],
    'Utility': ['lodash', 'moment', 'dayjs', 'uuid', 'chalk', 'dotenv', 'semver'],
    'Build Tool': ['webpack', 'vite', 'esbuild', 'rollup', 'parcel', 'typescript', 'babel'],
    'Testing': ['jest', 'mocha', 'chai', 'vitest', 'cypress', 'playwright'],
    'Linting': ['eslint', 'prettier', 'stylelint'],
  };

  const lower = name.toLowerCase();
  for (const [cat, names] of Object.entries(categories)) {
    if (names.some(n => lower.includes(n))) return cat;
  }
  return 'Other';
}

function findVulnerablePaths(roots: DependencyNode[], findings: Finding[]): VulnerablePath[] {
  const paths: VulnerablePath[] = [];

  const traverse = (node: DependencyNode, currentPath: string[]): void => {
    const current = [...currentPath, node.name];
    if (node.vulnerabilities.length > 0) {
      for (const vid of node.vulnerabilities) {
        const finding = findings.find(f => f.id === vid);
        paths.push({
          path: current,
          findingId: vid,
          severity: finding?.severity || 'UNKNOWN',
        });
      }
    }
    for (const child of node.children) {
      const childNode = roots.find(r => r.name === child.to);
      if (childNode) traverse(childNode, current);
    }
  };

  for (const root of roots) {
    traverse(root, []);
  }

  return paths;
}

export function formatDependencyGraph(graph: DependencyGraph): string {
  const lines: string[] = [];
  lines.push('Application');
  lines.push('│');

  for (let i = 0; i < graph.roots.length; i++) {
    const root = graph.roots[i];
    const prefix = i === graph.roots.length - 1 ? '└── ' : '├── ';
    const vulnMark = root.vulnerabilities.length > 0 ? ' ⚠' : '';
    lines.push(`${prefix}${root.name}@${root.version}${vulnMark} (${root.category})`);
  }

  if (graph.vulnerablePaths.length > 0) {
    lines.push('');
    lines.push('VULNERABLE DEPENDENCIES');
    lines.push('');
    for (const vp of graph.vulnerablePaths) {
      lines.push(`  ${vp.severity.padEnd(8)} ${vp.path.join(' → ')}`);
      lines.push(`           ${vp.findingId}`);
    }
  }

  return lines.join('\n');
}
