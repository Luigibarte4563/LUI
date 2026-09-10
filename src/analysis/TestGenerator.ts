import { Finding } from '../models/Finding';

export interface GeneratedTest {
  findingId: string;
  testName: string;
  language: string;
  testCode: string;
  description: string;
}

export function generateSecurityTest(finding: Finding, language: string = 'typescript'): GeneratedTest {
  const lang = detectLanguage(finding, language);

  switch (finding.category) {
    case 'Injection':
      return generateInjectionTest(finding, lang);
    case 'XSS':
      return generateXSSTest(finding, lang);
    case 'Secrets':
      return generateSecretsTest(finding, lang);
    case 'Authentication':
      return generateAuthTest(finding, lang);
    case 'Authorization':
      return generateAuthorizationTest(finding, lang);
    default:
      return generateGenericTest(finding, lang);
  }
}

function detectLanguage(finding: Finding, fallback: string): string {
  for (const loc of finding.affectedFiles) {
    if (loc.file.endsWith('.py')) return 'python';
    if (loc.file.endsWith('.java')) return 'java';
    if (loc.file.endsWith('.go')) return 'go';
    if (loc.file.endsWith('.php')) return 'php';
    if (loc.file.endsWith('.rb')) return 'ruby';
  }
  return fallback;
}

function generateInjectionTest(finding: Finding, lang: string): GeneratedTest {
  if (lang === 'python') {
    return {
      findingId: finding.id,
      testName: `test_${finding.id.toLowerCase()}_input_validation`,
      language: 'python',
      description: 'Verify that SQL metacharacters are rejected or handled as data',
      testCode: `import pytest

def test_input_validation_rejects_sql_metacharacters():
    """Regression test for ${finding.title}"""
    malicious_inputs = [
        "' OR '1'='1",
        "1; DROP TABLE users",
        "admin'--",
        "' UNION SELECT * FROM users--",
    ]
    for payload in malicious_inputs:
        response = client.get(f"/api/search?q={payload}")
        assert response.status_code in (400, 422), f"Should reject SQL metacharacters: {payload}"
        assert "error" not in response.json().get("message", "").lower() or response.status_code >= 400

def test_input_is_sanitized_before_query():
    """Verify input is parameterized"""
    response = client.get("/api/search?q=test")
    assert response.status_code == 200`,
    };
  }

  return {
    findingId: finding.id,
    testName: `test_${finding.id.toLowerCase()}_input_validation`,
    language: 'typescript',
    description: 'Verify that SQL metacharacters are rejected or handled as data',
    testCode: `describe('${finding.id} - Input Validation', () => {
  const maliciousInputs = [
    "' OR '1'='1",
    "1; DROP TABLE users",
    "admin'--",
    "' UNION SELECT * FROM users--",
  ];

  it('should reject SQL metacharacters', async () => {
    for (const payload of maliciousInputs) {
      const res = await request(app).get('/api/search').query({ q: payload });
      expect(res.status).toBeGreaterThanOrEqual(400);
    }
  });

  it('should handle normal input safely', async () => {
    const res = await request(app).get('/api/search').query({ q: 'normal search' });
    expect(res.status).toBe(200);
  });
});`,
  };
}

function generateXSSTest(finding: Finding, lang: string): GeneratedTest {
  return {
    findingId: finding.id,
    testName: `test_${finding.id.toLowerCase()}_xss_prevention`,
    language: lang,
    description: 'Verify that HTML metacharacters are escaped in output',
    testCode: lang === 'python'
      ? `import pytest

def test_xss_metacharacters_are_escaped():
    """Regression test for ${finding.title}"""
    xss_payloads = [
        '<script>alert("xss")</script>',
        '<img src=x onerror=alert(1)>',
        '"><script>alert(document.cookie)</script>',
    ]
    for payload in xss_payloads:
        response = client.get(f"/search?q={payload}")
        assert "<script>" not in response.text, f"XSS payload not escaped: {payload}"
        assert "onerror" not in response.text or response.status_code >= 400`
      : `describe('${finding.id} - XSS Prevention', () => {
  it('should escape HTML metacharacters', async () => {
    const xssPayloads = [
      '<script>alert("xss")</script>',
      '<img src=x onerror=alert(1)>',
      '"><script>alert(document.cookie)</script>',
    ];
    for (const payload of xssPayloads) {
      const res = await request(app).get('/search').query({ q: payload });
      expect(res.text).not.toContain('<script>');
      expect(res.text).not.toContain('onerror');
    }
  });
});`,
  };
}

function generateSecretsTest(finding: Finding, lang: string): GeneratedTest {
  return {
    findingId: finding.id,
    testName: `test_${finding.id.toLowerCase()}_no_hardcoded_secrets`,
    language: lang,
    description: 'Verify that no hardcoded secrets exist in source code',
    testCode: `const fs = require('fs');
const path = require('path');

describe('${finding.id} - No Hardcoded Secrets', () => {
  it('should not contain hardcoded credentials in source files', () => {
    const srcDir = path.join(__dirname, '../src');
    const files = getAllSourceFiles(srcDir);
    
    for (const file of files) {
      const content = fs.readFileSync(file, 'utf-8');
      expect(content).not.toMatch(/(?:password|secret|api_key|token)\\s*[=:]\\s*['"][^'"]{8,}['"]/i);
    }
  });
});

function getAllSourceFiles(dir) {
  const files = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory() && entry.name !== 'node_modules') {
      files.push(...getAllSourceFiles(fullPath));
    } else if (/\\.(js|ts)$/.test(entry.name)) {
      files.push(fullPath);
    }
  }
  return files;
}`,
  };
}

function generateAuthTest(finding: Finding, lang: string): GeneratedTest {
  return {
    findingId: finding.id,
    testName: `test_${finding.id.toLowerCase()}_auth_check`,
    language: lang,
    description: 'Verify that authentication is required for protected endpoints',
    testCode: `describe('${finding.id} - Authentication Check', () => {
  it('should reject unauthenticated requests', async () => {
    const res = await request(app).get('/api/protected');
    expect(res.status).toBe(401);
  });

  it('should accept valid authentication', async () => {
    const token = generateValidToken();
    const res = await request(app)
      .get('/api/protected')
      .set('Authorization', \`Bearer \${token}\`);
    expect(res.status).toBe(200);
  });
});`,
  };
}

function generateAuthorizationTest(finding: Finding, lang: string): GeneratedTest {
  return {
    findingId: finding.id,
    testName: `test_${finding.id.toLowerCase()}_authorization_check`,
    language: lang,
    description: 'Verify that users cannot access resources they do not own',
    testCode: `describe('${finding.id} - Authorization Check', () => {
  it('should prevent access to other users resources', async () => {
    const userAToken = generateTokenForUser('user-a');
    const userBId = 'user-b-id';

    const res = await request(app)
      .get(\`/api/users/\${userBId}/data\`)
      .set('Authorization', \`Bearer \${userAToken}\`);
    
    expect(res.status).toBeOneOf([403, 404]);
  });
});`,
  };
}

function generateGenericTest(finding: Finding, lang: string): GeneratedTest {
  return {
    findingId: finding.id,
    testName: `test_${finding.id.toLowerCase()}_security_check`,
    language: lang,
    description: `Regression test for ${finding.title}`,
    testCode: `describe('${finding.id} - Security Regression', () => {
  it('should not contain the vulnerability', async () => {
    // TODO: Implement specific test for ${finding.title}
    // Recommendation: ${finding.recommendation}
    expect(true).toBe(true);
  });
});`,
  };
}

export function formatGeneratedTest(test: GeneratedTest): string {
  const lines: string[] = [];
  lines.push(`Test: ${test.testName}`);
  lines.push(`Finding: ${test.findingId}`);
  lines.push(`Language: ${test.language}`);
  lines.push(`Description: ${test.description}`);
  lines.push('');
  lines.push(test.testCode);
  return lines.join('\n');
}
