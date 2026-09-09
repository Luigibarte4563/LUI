import { findVulnerabilities, isVersionAffected, VULNERABILITY_DATABASE, normalizeVersion } from '../src/knowledge/vulnerabilityDatabase';

describe('Vulnerability database', () => {
  test('contains a broad set of curated vulnerabilities', () => {
    expect(VULNERABILITY_DATABASE.length).toBeGreaterThanOrEqual(45);
    expect(VULNERABILITY_DATABASE.every(v => v.package && v.versions.length > 0 && v.cwe)).toBe(true);
  });

  test('covers multiple ecosystems', () => {
    const packageNames = VULNERABILITY_DATABASE.map(v => v.package.toLowerCase());
    expect(packageNames).toContain('lodash');
    expect(packageNames).toContain('django');
    expect(packageNames).toContain('requests');
    expect(packageNames).toContain('flask');
  });

  test('flags affected versions', () => {
    expect(findVulnerabilities('lodash', '4.17.19').length).toBeGreaterThan(0);
    expect(findVulnerabilities('express', '4.17.1').length).toBeGreaterThan(0);
    expect(findVulnerabilities('jsonwebtoken', '8.5.1').map(v => v.cve)).toContain('CVE-2022-23539');
  });

  test('does not flag fixed versions', () => {
    expect(findVulnerabilities('lodash', '4.17.21')).toHaveLength(0);
    expect(findVulnerabilities('express', '4.19.2')).toHaveLength(0);
    expect(findVulnerabilities('shell-quote', '1.8.1')).toHaveLength(0);
  });

  test('handles multiple version ranges per package', () => {
    expect(isVersionAffected('2.6.0', ['>=2.0.0 <2.6.7', '>=3.0.0 <3.3.1'])).toBe(true);
    expect(isVersionAffected('3.2.9', ['>=2.0.0 <2.6.7', '>=3.0.0 <3.3.1'])).toBe(true);
    expect(isVersionAffected('3.3.1', ['>=2.0.0 <2.6.7', '>=3.0.0 <3.3.1'])).toBe(false);
  });

  test('resolves range/careat/underscore style version strings', () => {
    expect(findVulnerabilities('lodash', '^4.17.19').length).toBeGreaterThan(0);
    expect(findVulnerabilities('lodash', '~4.17.19').length).toBeGreaterThan(0);
    expect(normalizeVersion('4.17.19').effectiveVersion).toBe('4.17.19');
  });

  test('never flags unresolvable or wildcard versions', () => {
    expect(findVulnerabilities('lodash', '*')).toHaveLength(0);
    expect(findVulnerabilities('lodash', 'latest')).toHaveLength(0);
    expect(findVulnerabilities('lodash', '')).toHaveLength(0);
  });

  test('is case-insensitive on package names', () => {
    expect(findVulnerabilities('Lodash', '4.17.19').length).toBeGreaterThan(0);
  });
});