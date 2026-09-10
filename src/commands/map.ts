import chalk from 'chalk';
import * as fs from 'fs';
import * as path from 'path';
import { ScanResult } from '../models/ScanResult';
import { Finding, Severity } from '../models/Finding';

export interface AttackSurfaceResult {
  public: EndpointGroup;
  authenticated: EndpointGroup;
  admin: EndpointGroup;
  external: ExternalService[];
  matrix: Array<{ method: string; path: string; hasAuth: boolean; hasAuthz: boolean; hasValidation: boolean }>;
}

export interface EndpointGroup {
  label: string;
  endpoints: string[];
}

export interface ExternalService {
  name: string;
  type: string;
}

const PUBLIC_PATTERNS = [
  /(?:\/login|\/register|\/signup|\/signin|\/auth|\/oauth|\/callback)/i,
  /(?:\/health|\/status|\/api\/products|\/api\/public|\/api\/search)/i,
  /(?:\/forgot-password|\/reset-password|\/verify-email)/i,
  /(?:\/index|\/|\/home|\/about|\/contact)/i,
];

const ADMIN_PATTERNS = [
  /(?:\/admin|\/dashboard|\/manage|\/cms|\/panel)/i,
  /(?:\/api\/users|\/api\/reports|\/api\/config|\/api\/settings)/i,
  /(?:\/api\/admin|\/api\/internal)/i,
];

export function buildAttackSurface(result: ScanResult): AttackSurfaceResult {
  const publicEndpoints: string[] = [];
  const authEndpoints: string[] = [];
  const adminEndpoints: string[] = [];
  const externalServices: ExternalService[] = [];
  const matrix: Array<{ method: string; path: string; hasAuth: boolean; hasAuthz: boolean; hasValidation: boolean }> = [];

  // Use discovered endpoints from scan metadata (Feature 20)
  if (result.endpoints && result.endpoints.length > 0) {
    for (const ep of result.endpoints) {
      const label = `${ep.method} ${ep.path}`;
      matrix.push(ep);

      if (ADMIN_PATTERNS.some(p => p.test(ep.path))) {
        adminEndpoints.push(label);
      } else if (PUBLIC_PATTERNS.some(p => p.test(ep.path))) {
        publicEndpoints.push(label);
      } else {
        authEndpoints.push(label);
      }
    }
  }

  // Supplement with findings that reference endpoints
  const endpointFindings = result.findings.filter(f =>
    f.category === 'API Security' && f.title.includes('Endpoint')
  );

  for (const finding of endpointFindings) {
    const match = finding.title.match(/(?:GET|POST|PUT|DELETE|PATCH|ANY)\s+(\S+)/);
    const endpoint = match ? match[0] : finding.title;
    if (!publicEndpoints.includes(endpoint) && !authEndpoints.includes(endpoint) && !adminEndpoints.includes(endpoint)) {
      if (ADMIN_PATTERNS.some(p => p.test(endpoint))) {
        adminEndpoints.push(endpoint);
      } else if (PUBLIC_PATTERNS.some(p => p.test(endpoint))) {
        publicEndpoints.push(endpoint);
      } else {
        authEndpoints.push(endpoint);
      }
    }
  }

  const tech = result.technologyProfile;
  for (const db of tech.databases) {
    externalServices.push({ name: db, type: 'Database' });
  }
  for (const method of tech.authMethods) {
    if (method.toLowerCase().includes('oauth') || method.toLowerCase().includes('firebase') || method.toLowerCase().includes('google')) {
      externalServices.push({ name: method, type: 'Authentication Provider' });
    }
  }

  if (publicEndpoints.length === 0 && authEndpoints.length === 0 && adminEndpoints.length === 0) {
    publicEndpoints.push('(No routes detected - add routes to your source code)');
  }

  return {
    public: { label: 'PUBLIC', endpoints: [...new Set(publicEndpoints)] },
    authenticated: { label: 'AUTHENTICATED', endpoints: [...new Set(authEndpoints)] },
    admin: { label: 'ADMIN', endpoints: [...new Set(adminEndpoints)] },
    external: externalServices,
    matrix,
  };
}

function extractEndpointsFromScanResult(result: ScanResult): string[] {
  const endpoints: string[] = [];
  const routeRegex = /(?:GET|POST|PUT|DELETE|PATCH)\s+(\S+)/gi;

  for (const finding of result.findings) {
    const matches = finding.title.matchAll(routeRegex);
    for (const match of matches) {
      endpoints.push(match[0]);
    }
  }

  return [...new Set(endpoints)];
}

export function printAttackSurface(surface: AttackSurfaceResult): void {
  console.log('');
  console.log(chalk.bold('  Lui Attack Surface'));
  console.log(chalk.gray('  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
  console.log('');

  printGroup(surface.public);
  printGroup(surface.authenticated);
  printGroup(surface.admin);

  if (surface.external.length > 0) {
    console.log(chalk.bold('  EXTERNAL SERVICES'));
    console.log('');
    for (const svc of surface.external) {
      console.log(`   ├── ${svc.name} (${svc.type})`);
    }
    console.log('');
  }

  if (surface.matrix && surface.matrix.length > 0) {
    console.log(chalk.bold('  ENDPOINT SECURITY MATRIX'));
    console.log('');
    console.log('  ' + chalk.gray('Endpoint'.padEnd(32) + 'Auth'.padEnd(8) + 'AuthZ'.padEnd(8) + 'Valid'));
    console.log(chalk.gray('  ' + '─'.repeat(56)));
    for (const ep of surface.matrix) {
      const label = `${ep.method} ${ep.path}`.padEnd(32);
      const auth = ep.hasAuth ? chalk.green('✓') : chalk.red('✗');
      const authz = ep.hasAuthz ? chalk.green('✓') : ep.hasAuth ? chalk.yellow('⚠') : chalk.gray('N/A');
      const valid = ep.hasValidation ? chalk.green('✓') : chalk.yellow('⚠');
      console.log(`  ${label}${auth}${' '.repeat(6)}${authz}${' '.repeat(6)}${valid}`);
    }
    console.log('');
  }
}

function printGroup(group: EndpointGroup): void {
  if (group.endpoints.length === 0) return;
  console.log(chalk.bold(`  ${group.label}`));
  console.log('');
  for (let i = 0; i < group.endpoints.length; i++) {
    const prefix = i === group.endpoints.length - 1 ? '└──' : '├──';
    console.log(`   ${prefix} ${group.endpoints[i]}`);
  }
  console.log('');
}
