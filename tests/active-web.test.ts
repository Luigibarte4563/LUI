import * as http from 'http';
import { AddressInfo } from 'net';
import { ActiveWebScanner } from '../src/scanners/ActiveWebScanner';
import { ScanContext } from '../src/scanners/BaseScanner';
import { ProjectProfile } from '../src/models/ProjectProfile';

let server: http.Server;
let baseUrl = '';

function createContext(url: string): ScanContext {
  const project = { rootPath: '', projectName: 'test' } as unknown as ProjectProfile;
  return {
    project,
    rootPath: '',
    scanType: 'standard',
    config: {},
    fileContents: new Map(),
    url,
  };
}

beforeAll((done) => {
  server = http.createServer((req, res) => {
    res.statusCode = 200;
    res.setHeader('Server', 'TestServer/1.0');
    res.setHeader('X-Powered-By', 'Express');
    res.setHeader('Content-Type', 'text/html');
    res.setHeader('Set-Cookie', ['session=abc123; Path=/', 'auth=xyz']);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.end('<!DOCTYPE html><html></html>');
  });
  server.listen(0, '127.0.0.1', () => {
    const address = server.address() as AddressInfo;
    baseUrl = `http://127.0.0.1:${address.port}/`;
    done();
  });
});

afterAll((done) => {
  server.close(() => done());
});

describe('ActiveWebScanner', () => {
  test('is enabled only when a URL is provided', () => {
    const scanner = new ActiveWebScanner('http://127.0.0.1:1/');
    expect(scanner.supported(createContext('http://127.0.0.1:1/'))).toBe(true);
    expect(scanner.supported(createContext(undefined as unknown as string))).toBe(false);
  });

  test('detects missing security headers', async () => {
    const scanner = new ActiveWebScanner(baseUrl);
    const findings = await scanner.scan(createContext(baseUrl));

    const ids = findings.map(f => f.id);
    expect(ids).toContain('LUI-WEB-001'); // HSTS
    expect(ids).toContain('LUI-WEB-002'); // X-Content-Type-Options
    expect(ids).toContain('LUI-WEB-003'); // clickjacking
    expect(ids).toContain('LUI-WEB-004'); // CSP on HTML
    expect(ids).toContain('LUI-WEB-005'); // Referrer-Policy
  });

  test('detects technology disclosure', async () => {
    const scanner = new ActiveWebScanner(baseUrl);
    const findings = await scanner.scan(createContext(baseUrl));

    const title = findings.map(f => f.title).join(' | ');
    expect(title).toContain('Server version disclosure');
    expect(title).toContain('X-Powered-By');
  });

  test('flags cookies missing security attributes', async () => {
    const scanner = new ActiveWebScanner(baseUrl);
    const findings = await scanner.scan(createContext(baseUrl));

    const cookieFindings = findings.filter(f => f.id === 'LUI-WEB-008');
    expect(cookieFindings.length).toBeGreaterThanOrEqual(2);
    expect(cookieFindings.some(f => f.evidence.some(e => e.includes('Secure')))).toBe(true);
    expect(cookieFindings.some(f => f.evidence.some(e => e.includes('HttpOnly')))).toBe(true);
  });

  test('flags wildcard CORS with credentials', async () => {
    const scanner = new ActiveWebScanner(baseUrl);
    const findings = await scanner.scan(createContext(baseUrl));

    const cors = findings.find(f => f.id === 'LUI-WEB-009');
    expect(cors).toBeDefined();
    expect(cors!.severity).toBe('HIGH');
  });

  test('returns no findings when the target is unreachable', async () => {
    const scanner = new ActiveWebScanner('http://127.0.0.1:1/');
    const findings = await scanner.scan(createContext('http://127.0.0.1:1/'));
    expect(findings).toHaveLength(0);
  });

  test('does not flag protections when headers are present', async () => {
    const secureServer = http.createServer((req, res) => {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('X-Frame-Options', 'DENY');
      res.setHeader('Content-Security-Policy', "default-src 'self'");
      res.setHeader('Set-Cookie', ['sid=abc; HttpOnly; Secure; SameSite=Lax; Path=/']);
      res.setHeader('Access-Control-Allow-Origin', 'https://trusted.example.com');
      res.end('ok');
    });

    await new Promise<void>((resolve) => secureServer.listen(0, '127.0.0.1', () => resolve()));
    const address = secureServer.address() as AddressInfo;
    const url = `http://127.0.0.1:${address.port}/`;

    try {
      const scanner = new ActiveWebScanner(url);
      const findings = await scanner.scan(createContext(url));

      expect(findings.find(f => f.id === 'LUI-WEB-001')).toBeUndefined();
      expect(findings.find(f => f.id === 'LUI-WEB-002')).toBeUndefined();
      expect(findings.find(f => f.id === 'LUI-WEB-003')).toBeUndefined();
      expect(findings.find(f => f.id === 'LUI-WEB-008')).toBeUndefined();
      expect(findings.find(f => f.id === 'LUI-WEB-009')).toBeUndefined();
    } finally {
      await new Promise<void>((resolve) => secureServer.close(() => resolve()));
    }
  }, 15000);
});