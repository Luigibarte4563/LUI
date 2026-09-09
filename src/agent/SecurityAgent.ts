import { Scanner, ScanContext } from '../scanners/BaseScanner';
import { Finding } from '../models/Finding';
import { ScanResult, TechnologyProfile } from '../models/ScanResult';
import { ProjectProfile } from '../models/ProjectProfile';
import { SecretScanner } from '../scanners/SecretScanner';
import { DependencyScanner } from '../scanners/DependencyScanner';
import { SASTScanner } from '../scanners/SASTScanner';
import { AuthScanner } from '../scanners/AuthScanner';
import { AuthorizationScanner } from '../scanners/AuthorizationScanner';
import { APIScanner } from '../scanners/APIScanner';
import { ConfigScanner } from '../scanners/ConfigScanner';
import { DockerScanner } from '../scanners/DockerScanner';
import { CICDScanner } from '../scanners/CICDScanner';
import { calculateScore, getSeveritySummary, getTopFindings } from '../analysis/Severity';
import { deduplicateFindings, correlateFindings, identifyAttackChains, AttackChain } from '../analysis/Deduplication';
import { analyzeDataFlows, applyTaintConfidence, DataFlow } from '../analysis/DataFlow';
import { ActiveWebScanner } from '../scanners/ActiveWebScanner';
import { LLMCorrelator } from '../ai/LLMCorrelator';
import { AIConfig, PrivacyConfig } from '../ai/types';
import * as fs from 'fs';
import * as path from 'path';

export interface ScanOptions {
  scanType: 'quick' | 'standard' | 'deep';
  category?: string;
  url?: string;
  excludes?: string[];
  ai?: AIConfig;
  privacy?: PrivacyConfig;
}

export interface ScanProgress {
  phase: string;
  total: number;
  current: number;
  status: 'pending' | 'running' | 'done' | 'error';
  finding?: Finding;
}

export class SecurityAgent {
  private project: ProjectProfile;
  private scanners: Scanner[] = [];
  private findings: Finding[] = [];
  private attackChains: AttackChain[] = [];
  private progressCallback?: (progress: ScanProgress) => void;

  constructor(project: ProjectProfile) {
    this.project = project;
    this.initializeScanners();
  }

  onProgress(callback: (progress: ScanProgress) => void): void {
    this.progressCallback = callback;
  }

  private initializeScanners(): void {
    this.scanners = [
      new SecretScanner(),
      new DependencyScanner(),
      new SASTScanner(),
      new AuthScanner(),
      new AuthorizationScanner(),
      new APIScanner(),
      new ConfigScanner(),
      new DockerScanner(),
      new CICDScanner(),
    ];
  }

  async scan(options: ScanOptions): Promise<ScanResult> {
    const startTime = Date.now();
    const scanContext: ScanContext = {
      project: this.project,
      rootPath: this.project.rootPath,
      scanType: options.scanType,
      config: { exclude: options.excludes || [] },
      fileContents: new Map(),
      url: options.url,
    };

    // Filter scanners based on options
    let activeScanners = this.getScannersForCategory(options.category, options.scanType);

    // Active web scanning: enabled when a URL is provided
    if (options.url) {
      activeScanners = [new ActiveWebScanner(options.url), ...activeScanners];
    }

    // Filter based on project technology
    activeScanners = activeScanners.filter(s => {
      if (s.supported) return s.supported(scanContext);
      return true;
    });

    const totalScanners = activeScanners.length;

    // Run scanners
    for (let i = 0; i < activeScanners.length; i++) {
      const scanner = activeScanners[i];
      this.reportProgress({
        phase: scanner.name,
        total: totalScanners,
        current: i + 1,
        status: 'running',
      });

      try {
        const scannerFindings = await scanner.scan(scanContext);
        this.findings.push(...scannerFindings);
        
        // Report high-risk findings immediately
        for (const finding of scannerFindings) {
          if (finding.severity === 'CRITICAL' || finding.severity === 'HIGH') {
            this.reportProgress({
              phase: scanner.name,
              total: totalScanners,
              current: i + 1,
              status: 'done',
              finding,
            });
          }
        }
      } catch (error) {
        this.reportProgress({
          phase: scanner.name,
          total: totalScanners,
          current: i + 1,
          status: 'error',
        });
      }
    }

    // Correlation phase
    this.reportProgress({
      phase: 'Correlation',
      total: totalScanners,
      current: totalScanners,
      status: 'running',
    });

    this.findings = deduplicateFindings(this.findings);
    this.findings = correlateFindings(this.findings);

    // Data flow analysis: upgrade confidence when a source-to-sink path is confirmed
    const dataFlows: DataFlow[] = analyzeDataFlows(this.findings, this.project.rootPath, (file) => {
      const absolute = path.isAbsolute(file) ? file : path.join(this.project.rootPath, file);
      for (const [key, content] of scanContext.fileContents.entries()) {
        if (key === absolute || key.endsWith('/' + file.replace(/\\/g, '/'))) {
          return content;
        }
      }
      try {
        const content = fs.readFileSync(absolute, 'utf-8');
        scanContext.fileContents.set(absolute, content);
        return content;
      } catch {
        return null;
      }
    });
    this.findings = applyTaintConfidence(this.findings, dataFlows);

    // LLM/AI correlation (opt-in, never blocks or falsifies the scan)
    let aiReport: string | null = null;
    let aiUsed = false;
    if (options.ai?.enabled && options.ai.provider !== 'disabled') {
      const correlator = new LLMCorrelator(options.ai, options.privacy || {});
      const result = await correlator.correlate(
        this.findings,
        [...this.project.technology.languages, ...this.project.technology.frameworks],
        this.detectAttackSurfaces()
      );
      if (result) {
        aiReport = result.text;
        aiUsed = true;
      }
    }

    this.attackChains = identifyAttackChains(this.findings);

    // Calculate score
    const { score, label } = calculateScore(this.findings);
    const summary = getSeveritySummary(this.findings);
    const duration = Date.now() - startTime;

    return {
      tool: 'Lui',
      version: '0.1.0',
      target: this.project.rootPath,
      scanType: options.scanType,
      score,
      scoreLabel: label,
      summary,
      findings: this.findings,
      scanDate: new Date().toISOString(),
      duration,
      technologyProfile: this.project.technology,
      attackSurfaces: this.detectAttackSurfaces(),
      attackChains: this.attackChains.map(c => ({
        id: c.id,
        title: c.title,
        description: c.description,
        confidence: c.confidence,
        impact: c.impact,
        steps: c.steps,
      })),
      metadata: {
        projectName: this.project.projectName,
        fileCount: this.project.fileCount,
        attackChainsCount: this.attackChains.length,
        dataFlows: dataFlows.map(f => ({
          source: f.source,
          sink: f.sink,
          file: f.file,
          sinkLine: f.sinkLine,
          confidence: f.confidence,
        })),
        activeScan: options.url ? true : false,
        aiAnalysis: aiUsed ? { enabled: true, report: aiReport, provider: options.ai!.provider } : { enabled: false },
      },
    };
  }

  private getScannersForCategory(category: string | undefined, scanType: string): Scanner[] {
    if (!category) {
      if (scanType === 'quick') {
        return this.scanners.filter(s => 
          ['secrets', 'dependencies', 'sast', 'configuration'].includes(s.category)
        );
      }
      return this.scanners;
    }

    const categoryMap: Record<string, string[]> = {
      secrets: ['secrets'],
      dependencies: ['dependencies'],
      code: ['sast'],
      auth: ['auth'],
      authorization: ['authorization'],
      api: ['api'],
      configuration: ['configuration'],
      docker: ['docker'],
      cicd: ['cicd'],
      web: ['web'],
    };

    const categories = categoryMap[category] || [category];
    return this.scanners.filter(s => categories.includes(s.category));
  }

  private detectAttackSurfaces(): string[] {
    const surfaces: string[] = [];
    const tech = this.project.technology;
    
    if (tech.frontend.length > 0) surfaces.push('Frontend');
    if (tech.backend.length > 0) surfaces.push('Backend API');
    if (tech.authMethods.length > 0) surfaces.push('Authentication');
    if (this.project.hasDockerfile) surfaces.push('Docker');
    if (this.project.hasCICD) surfaces.push('CI/CD');
    if (tech.databases.length > 0) surfaces.push('Database');
    
    return surfaces;
  }

  private reportProgress(progress: ScanProgress): void {
    if (this.progressCallback) {
      this.progressCallback(progress);
    }
  }

  getAttackChains(): AttackChain[] {
    return this.attackChains;
  }
}
