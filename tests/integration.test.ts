import * as path from 'path';
import { ProjectDiscovery } from '../src/discovery/ProjectDiscovery';
import { SecurityAgent } from '../src/agent/SecurityAgent';
import { ConfigLoader } from '../src/config/ConfigLoader';

const VULNERABLE_PATH = path.join(__dirname, 'fixtures', 'vulnerable-node');
const SECURE_PATH = path.join(__dirname, 'fixtures', 'secure-project');

describe('Integration: Vulnerable Project', () => {
  test('detects multiple security issues', async () => {
    const configLoader = new ConfigLoader(VULNERABLE_PATH);
    const discovery = new ProjectDiscovery(VULNERABLE_PATH, configLoader.getExcludes());
    const project = await discovery.discover();
    
    const agent = new SecurityAgent(project);
    const result = await agent.scan({ scanType: 'deep' });
    
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.score).toBeLessThan(100);
    expect(result.summary.CRITICAL + result.summary.HIGH).toBeGreaterThan(0);
  });

  test('detects secrets', async () => {
    const configLoader = new ConfigLoader(VULNERABLE_PATH);
    const discovery = new ProjectDiscovery(VULNERABLE_PATH, configLoader.getExcludes());
    const project = await discovery.discover();
    
    const agent = new SecurityAgent(project);
    const result = await agent.scan({ scanType: 'standard', category: 'secrets' });
    
    const secretFindings = result.findings.filter(f => f.category === 'Secrets');
    expect(secretFindings.length).toBeGreaterThan(0);
  });

  test('detects Docker issues', async () => {
    const configLoader = new ConfigLoader(VULNERABLE_PATH);
    const discovery = new ProjectDiscovery(VULNERABLE_PATH, configLoader.getExcludes());
    const project = await discovery.discover();
    
    const agent = new SecurityAgent(project);
    const result = await agent.scan({ scanType: 'standard', category: 'docker' });
    
    const dockerFindings = result.findings.filter(f => f.category === 'Docker Security');
    expect(dockerFindings.length).toBeGreaterThan(0);
  });
});

describe('Integration: Secure Project', () => {
  test('produces fewer findings', async () => {
    const configLoader = new ConfigLoader(SECURE_PATH);
    const discovery = new ProjectDiscovery(SECURE_PATH, configLoader.getExcludes());
    const project = await discovery.discover();
    
    const agent = new SecurityAgent(project);
    const result = await agent.scan({ scanType: 'standard' });
    
    // Secure project should have higher score
    expect(result.score).toBeGreaterThan(70);
  });
});

describe('Integration: Technology Detection', () => {
  test('detects Node.js project', async () => {
    const configLoader = new ConfigLoader(VULNERABLE_PATH);
    const discovery = new ProjectDiscovery(VULNERABLE_PATH, configLoader.getExcludes());
    const project = await discovery.discover();
    
    expect(project.technology.languages).toContain('JavaScript');
    expect(project.technology.frameworks).toContain('Express');
  });
});
