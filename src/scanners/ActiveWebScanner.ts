import * as http from 'http';
import * as https from 'https';
import { URL } from 'url';
import { BaseScanner, ScanContext } from './BaseScanner';
import { Finding, createFinding } from '../models/Finding';

interface WebResponse {
  url: string;
  statusCode: number;
  headers: http.IncomingHttpHeaders;
  body: string;
}

interface CookieInfo {
  name: string;
  raw: string;
  httpOnly: boolean;
  secure: boolean;
  sameSite: boolean;
}

export class ActiveWebScanner extends BaseScanner {
  private findingCounter = 0;

  constructor(private targetUrl: string) {
    super('Active Web Scanner', 'web', 'Performs safe passive checks against a running web application');
  }

  supported(context: ScanContext): boolean {
    return !!context.url;
  }

  async scan(context: ScanContext): Promise<Finding[]> {
    this.findingCounter = 0;
    const findings: Finding[] = [];

    try {
      const response = await this.fetch(context.url || this.targetUrl, 0);
      if (!response) return findings;

      findings.push(...this.checkSecurityHeaders(response));
      findings.push(...this.checkCookies(response));
      findings.push(...this.checkCors(response));

      return findings;
    } catch {
      return findings;
    }
  }

  private fetch(url: string, redirects: number): Promise<WebResponse | null> {
    return new Promise((resolve) => {
      let target: URL;
      try {
        target = new URL(url);
      } catch {
        resolve(null);
        return;
      }

      const lib = target.protocol === 'https:' ? https : http;
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10000);

      const request = lib.get(
        target,
        { headers: { 'User-Agent': 'Lui-Security-Auditor/0.1', 'Accept': '*/*' }, signal: controller.signal },
        (res) => {
          const status = res.statusCode || 0;

          if (status >= 300 && status < 400 && res.headers.location && redirects < 3) {
            res.resume();
            clearTimeout(timeout);
            const nextUrl = new URL(res.headers.location, target).toString();
            resolve(this.fetch(nextUrl, redirects + 1));
            return;
          }

          let body = '';
          res.setEncoding('utf8');
          res.on('data', (chunk: string) => {
            body += chunk;
            if (body.length > 200000) {
              res.destroy();
            }
          });
          res.on('end', () => {
            clearTimeout(timeout);
            resolve({
              url: target.toString(),
              statusCode: status,
              headers: res.headers,
              body,
            });
          });
          res.on('error', () => {
            clearTimeout(timeout);
            resolve(null);
          });
        }
      );

      request.on('error', () => {
        clearTimeout(timeout);
        resolve(null);
      });
    });
  }

  private checkSecurityHeaders(response: WebResponse): Finding[] {
    const findings: Finding[] = [];
    const headers = response.headers;
    const isHtml = (headers['content-type'] || '').includes('text/html');

    if (!headers['strict-transport-security']) {
      findings.push(this.makeFinding(
        'LUI-WEB-001',
        'Missing HTTP Strict Transport Security (HSTS) header',
        'MEDIUM',
        'The server does not send the Strict-Transport-Security header, allowing protocol downgrade attacks and HTTPS stripping.',
        response.url,
        [`Response URL: ${response.url}`, 'Strict-Transport-Security header is missing']
      ));
    }

    if (!headers['x-content-type-options']) {
      findings.push(this.makeFinding(
        'LUI-WEB-002',
        'Missing X-Content-Type-Options header',
        'MEDIUM',
        'The server does not send X-Content-Type-Options: nosniff, allowing MIME sniffing attacks.',
        response.url,
        ['X-Content-Type-Options header is missing']
      ));
    }

    const frameOptions = headers['x-frame-options'];
    const csp = String(headers['content-security-policy'] || '');
    if (!frameOptions && !(csp && /frame-ancestors[\s'"]*(?:'self'|\S+)/i.test(csp))) {
      findings.push(this.makeFinding(
        'LUI-WEB-003',
        'Missing clickjacking protection',
        'MEDIUM',
        'The server does not send X-Frame-Options or a Content-Security-Policy with frame-ancestors, allowing clickjacking.',
        response.url,
        ['X-Frame-Options header is missing', 'Content-Security-Policy frame-ancestors is missing or ineffective']
      ));
    }

    if (isHtml && !csp) {
      findings.push(this.makeFinding(
        'LUI-WEB-004',
        'Missing Content-Security-Policy header',
        'LOW',
        'The application serves HTML without a Content-Security-Policy, increasing XSS impact.',
        response.url,
        ['Content-Security-Policy header is missing']
      ));
    }

    if (!headers['referrer-policy']) {
      findings.push(this.makeFinding(
        'LUI-WEB-005',
        'Missing Referrer-Policy header',
        'LOW',
        'The server does not send a Referrer-Policy header, which may leak URL query strings to third parties.',
        response.url,
        ['Referrer-Policy header is missing']
      ));
    }

    if (headers.server) {
      findings.push(this.makeFinding(
        'LUI-WEB-006',
        'Server version disclosure',
        'LOW',
        'The server discloses its software in the Server header, aiding targeted attacks.',
        response.url,
        [`Server: ${String(headers.server)}`]
      ));
    }

    if (headers['x-powered-by']) {
      findings.push(this.makeFinding(
        'LUI-WEB-007',
        'Technology disclosure via X-Powered-By',
        'LOW',
        'The application exposes framework details via the X-Powered-By header.',
        response.url,
        [`X-Powered-By: ${String(headers['x-powered-by'])}`]
      ));
    }

    return findings;
  }

  private checkCookies(response: WebResponse): Finding[] {
    const findings: Finding[] = [];
    const setCookies = response.headers['set-cookie'];
    if (!setCookies || setCookies.length === 0) return findings;

    const cookies: CookieInfo[] = setCookies.map(raw => {
      const name = (raw.split('=')[0] || '').trim();
      return {
        name,
        raw,
        httpOnly: /;\s*HttpOnly/i.test(raw),
        secure: /;\s*Secure/i.test(raw),
        sameSite: /;\s*SameSite=/i.test(raw),
      };
    });

    for (const cookie of cookies) {
      const missing: string[] = [];
      if (!cookie.httpOnly) missing.push('HttpOnly');
      if (!cookie.secure) missing.push('Secure');
      if (!cookie.sameSite) missing.push('SameSite');

      if (missing.length > 0) {
        findings.push(this.makeFinding(
          'LUI-WEB-008',
          `Cookie "${cookie.name}" is missing security attributes`,
          missing.includes('Secure') ? 'HIGH' : 'MEDIUM',
          `The cookie is set without ${missing.join(', ')}, exposing it to theft or session manipulation.`,
          response.url,
          [`Cookie: ${cookie.name}`, `Missing: ${missing.join(', ')}`]
        ));
      }
    }

    return findings;
  }

  private checkCors(response: WebResponse): Finding[] {
    const findings: Finding[] = [];
    const headers = response.headers;
    const allowOrigin = headers['access-control-allow-origin'];
    const allowCredentials = String(headers['access-control-allow-credentials'] || '').toLowerCase();

    if (allowOrigin === '*' && allowCredentials === 'true') {
      findings.push(this.makeFinding(
        'LUI-WEB-009',
        'Permissive CORS configuration with credentials',
        'HIGH',
        'The server allows any origin together with credentials, enabling cross-origin data theft.',
        response.url,
        ['Access-Control-Allow-Origin: *', 'Access-Control-Allow-Credentials: true']
      ));
    } else if (typeof allowOrigin === 'string' && allowOrigin !== '*') {
      findings.push(this.makeFinding(
        'LUI-WEB-010',
        'Reflective CORS configuration',
        'MEDIUM',
        'The Access-Control-Allow-Origin header echoes request origins, which can allow unauthorized cross-origin reads.',
        response.url,
        [`Access-Control-Allow-Origin: ${allowOrigin}`]
      ));
    }

    return findings;
  }

  private makeFinding(id: string, title: string, severity: 'HIGH' | 'MEDIUM' | 'LOW', description: string, url: string, evidence: string[]): Finding {
    this.findingCounter++;
    return createFinding({
      id,
      title,
      severity,
      confidence: 'HIGH',
      category: 'Web Security',
      type: 'confirmed',
      description,
      impact: 'Active application configuration issues can be exploited by remote attackers.',
      affectedFiles: [{ file: url }],
      evidence,
      recommendation: 'Apply the security headers and hardening guidance described in the finding.',
      references: ['https://owasp.org/www-project-secure-headers/'],
      status: 'open',
      scanner: 'ActiveWebScanner',
      timestamp: Date.now(),
    });
  }
}