export interface SecurityProfile {
  name: string;
  description: string;
  scanners: string[];
  scanType: 'quick' | 'standard' | 'deep';
  failOn: string;
  categories: string[];
}

export const SECURITY_PROFILES: Record<string, SecurityProfile> = {
  startup: {
    name: 'startup',
    description: 'Quick scan for early-stage projects',
    scanners: ['secrets', 'dependencies', 'sast'],
    scanType: 'quick',
    failOn: 'high',
    categories: ['secrets', 'dependencies', 'code'],
  },
  webapp: {
    name: 'webapp',
    description: 'Full security audit for web applications',
    scanners: ['secrets', 'dependencies', 'sast', 'auth', 'authorization', 'api', 'configuration', 'docker'],
    scanType: 'deep',
    failOn: 'high',
    categories: ['secrets', 'dependencies', 'code', 'auth', 'authorization', 'api', 'configuration', 'docker'],
  },
  api: {
    name: 'api',
    description: 'API-focused security scan',
    scanners: ['secrets', 'dependencies', 'sast', 'auth', 'authorization', 'api'],
    scanType: 'standard',
    failOn: 'high',
    categories: ['secrets', 'dependencies', 'code', 'auth', 'authorization', 'api'],
  },
  enterprise: {
    name: 'enterprise',
    description: 'Comprehensive enterprise security audit',
    scanners: ['secrets', 'dependencies', 'sast', 'auth', 'authorization', 'api', 'configuration', 'docker', 'cicd'],
    scanType: 'deep',
    failOn: 'medium',
    categories: ['secrets', 'dependencies', 'code', 'auth', 'authorization', 'api', 'configuration', 'docker', 'cicd'],
  },
  ci: {
    name: 'ci',
    description: 'Fast CI/CD pipeline scan',
    scanners: ['secrets', 'dependencies'],
    scanType: 'quick',
    failOn: 'critical',
    categories: ['secrets', 'dependencies'],
  },
  mobile: {
    name: 'mobile',
    description: 'Mobile app security scan',
    scanners: ['secrets', 'dependencies', 'sast', 'auth', 'configuration'],
    scanType: 'standard',
    failOn: 'high',
    categories: ['secrets', 'dependencies', 'code', 'auth', 'configuration'],
  },
  docker: {
    name: 'docker',
    description: 'Container and orchestration security',
    scanners: ['secrets', 'docker', 'cicd', 'configuration'],
    scanType: 'standard',
    failOn: 'high',
    categories: ['secrets', 'docker', 'cicd', 'configuration'],
  },
};

export function getProfile(name: string): SecurityProfile | null {
  return SECURITY_PROFILES[name.toLowerCase()] || null;
}

export function listProfiles(): SecurityProfile[] {
  return Object.values(SECURITY_PROFILES);
}
