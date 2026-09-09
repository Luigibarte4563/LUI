import { Finding } from '../models/Finding';

export function deduplicateFindings(findings: Finding[]): Finding[] {
  const seen = new Map<string, Finding>();
  
  for (const finding of findings) {
    const key = `${finding.title}|${finding.affectedFiles[0]?.file || ''}|${finding.affectedFiles[0]?.line || 0}`;
    const existing = seen.get(key);
    
    if (!existing) {
      seen.set(key, finding);
    } else {
      // Keep the one with higher confidence
      if (getConfidenceWeight(finding.confidence) > getConfidenceWeight(existing.confidence)) {
        seen.set(key, finding);
      }
    }
  }
  
  return Array.from(seen.values());
}

function getConfidenceWeight(confidence: string): number {
  switch (confidence) {
    case 'HIGH': return 3;
    case 'MEDIUM': return 2;
    case 'LOW': return 1;
    default: return 0;
  }
}

export function correlateFindings(findings: Finding[]): Finding[] {
  // Identify potential attack chains
  const findingsCopy = [...findings];
  
  // Check for XSS + session token exposure chains
  const xssFindings = findings.filter(f => f.category === 'XSS');
  const authFindings = findings.filter(f => f.category === 'Authentication' && f.title.includes('localStorage'));
  
  if (xssFindings.length > 0 && authFindings.length > 0) {
    // This is a potential chain - we don't create a new finding, just note it
  }
  
  // Check for SQL injection + authorization bypass chains
  const sqliFindings = findings.filter(f => f.title.includes('SQL Injection'));
  const authzFindings = findings.filter(f => f.category === 'Authorization');
  
  if (sqliFindings.length > 0 && authzFindings.length > 0) {
    // This is a potential chain
  }

  return findingsCopy;
}

export function identifyAttackChains(findings: Finding[]): AttackChain[] {
  const chains: AttackChain[] = [];
  const activeFindings = findings.filter(f => f.status !== 'suppressed');

  // Chain: XSS -> Session Hijacking
  const xssFindings = activeFindings.filter(f => f.category === 'XSS');
  const sessionFindings = activeFindings.filter(f => 
    f.category === 'Authentication' && 
    (f.title.includes('localStorage') || f.title.includes('cookie') || f.title.includes('token'))
  );
  
  if (xssFindings.length > 0 && sessionFindings.length > 0) {
    chains.push({
      id: `CHAIN-${chains.length + 1}`,
      title: 'XSS to Session Hijacking',
      description: 'A stored or reflected XSS vulnerability could be used to steal session tokens stored in localStorage or cookies.',
      steps: [...xssFindings.slice(0, 1), ...sessionFindings.slice(0, 1)],
      confidence: 'MEDIUM',
      impact: 'Account takeover through session hijacking',
    });
  }

  // Chain: SQL Injection + Authorization Bypass
  const sqliFindings = activeFindings.filter(f => f.title.includes('SQL Injection'));
  const authzFindings = activeFindings.filter(f => f.category === 'Authorization');
  
  if (sqliFindings.length > 0 && authzFindings.length > 0) {
    chains.push({
      id: `CHAIN-${chains.length + 1}`,
      title: 'SQL Injection to Authorization Bypass',
      description: 'SQL injection could be used to bypass authorization checks and access unauthorized data.',
      steps: [...sqliFindings.slice(0, 1), ...authzFindings.slice(0, 1)],
      confidence: 'MEDIUM',
      impact: 'Unauthorized data access and privilege escalation',
    });
  }

  // Chain: Information Disclosure + Credential Theft
  const infoFindings = activeFindings.filter(f => f.category === 'Information Disclosure' || f.category === 'Secrets');
  const authFindings = activeFindings.filter(f => f.category === 'Authentication');
  
  if (infoFindings.length > 0 && authFindings.length > 0) {
    chains.push({
      id: `CHAIN-${chains.length + 1}`,
      title: 'Information Disclosure to Credential Theft',
      description: 'Exposed credentials or sensitive information could be used to compromise authentication.',
      steps: [...infoFindings.slice(0, 1), ...authFindings.slice(0, 1)],
      confidence: 'LOW',
      impact: 'Credential theft and unauthorized access',
    });
  }

  return chains;
}

export interface AttackChain {
  id: string;
  title: string;
  description: string;
  steps: Finding[];
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  impact: string;
}
