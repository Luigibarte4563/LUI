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
import { APIDiscoveryScanner } from '../scanners/APIDiscoveryScanner';
import { calculateScore, getSeveritySummary, getTopFindings } from '../analysis/Severity';
import { deduplicateFindings, correlateFindings, identifyAttackChains, AttackChain } from '../analysis/Deduplication';
import { analyzeDataFlows, applyTaintConfidence, DataFlow } from '../analysis/DataFlow';
import { buildEvidenceExplanation, EvidenceExplanation } from '../analysis/EvidenceEngine';
import { buildContextGraph, SecurityContextGraph } from '../analysis/ContextGraph';
import { prioritizeFindings, RiskPriority } from '../analysis/RiskPrioritization';
import { buildDependencyGraph, DependencyGraph } from '../analysis/DependencyGraph';
import { loadLifecycleStore, initializeLifecycle, LifecycleStore } from '../analysis/Lifecycle';
import { ActiveWebScanner } from '../scanners/ActiveWebScanner';
import { LLMCorrelator } from '../ai/LLMCorrelator';
import { LLMAnalyzer, AnalysisResult } from '../ai/LLMAnalyzer';
import { AIConfig, PrivacyConfig } from '../ai/types';
import { PluginRegistry } from '../plugins/PluginRegistry';
import * as fs from 'fs';
import * as path from 'path';

export interface ScanOptions {
  scanType: 'quick' | 'standard' | 'deep';
  category?: string;
  url?: string;
  excludes?: string[];
  ai?: AIConfig;
  privacy?: PrivacyConfig;
  profile?: string;
  incremental?: boolean;
  developer?: boolean;
  dynamicCve?: boolean;
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
  private pluginRegistry: PluginRegistry;

  constructor(project: ProjectProfile, pluginRegistry?: PluginRegistry) {
    this.project = project;
    this.pluginRegistry = pluginRegistry || new PluginRegistry();
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
      new APIDiscoveryScanner(),
    ];
  }

  async scan(options: ScanOptions): Promise<ScanResult> {
    const startTime = Date.now();
    const scanContext: ScanContext = {
      project: this.project,
      rootPath: this.project.rootPath,
      scanType: options.scanType,
      config: {
        exclude: options.excludes || [],
        dynamic_cve: options.dynamicCve,
      },
      fileContents: new Map(),
      url: options.url,
      ai: options.ai,
      privacy: options.privacy,
    };

    // Run plugin before-scan hooks
    await this.pluginRegistry.runBeforeScanHooks(scanContext);

    // Filter scanners based on options
    let activeScanners = this.getScannersForCategory(options.category, options.scanType);

    // Active web scanning: enabled when a URL is provided
    if (options.url) {
      activeScanners = [new ActiveWebScanner(options.url), ...activeScanners];
    }

    // Add plugin scanners
    activeScanners = [...activeScanners, ...this.pluginRegistry.getScanners()];

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

    // Feature 1: Evidence Engine - build explanations for each finding
    const evidenceExplanations: EvidenceExplanation[] = [];
    for (const finding of this.findings) {
      const explanation = buildEvidenceExplanation(finding, dataFlows, (file) => {
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
      evidenceExplanations.push(explanation);
    }

    // Feature 2: Security Context Graph
    const contextGraph = buildContextGraph(this.findings, (file) => {
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

    // Feature 19: Risk Prioritization
    const riskPriorities = prioritizeFindings(this.findings, dataFlows);
    for (const rp of riskPriorities) {
      const finding = this.findings.find(f => f.id === rp.findingId);
      if (finding) {
        finding.riskPriority = rp.priority;
      }
    }

    // Feature 18: Dependency Graph
    const dependencyGraph = buildDependencyGraph(this.project.rootPath, this.findings);

    // Feature 9: Vulnerability Lifecycle
    const lifecycleStore = loadLifecycleStore(this.project.rootPath);
    const updatedLifecycle = initializeLifecycle(lifecycleStore, this.findings.map(f => f.id));
    for (const finding of this.findings) {
      const lifecycle = updatedLifecycle.findings[finding.id];
      if (lifecycle) {
        finding.lifecycle = lifecycle.status;
      }
    }

    // LLM/AI correlation (opt-in, never blocks or falsifies the scan)
    let aiReport: string | null = null;
    let aiUsed = false;
    let aiValidatedFindings: Record<string, AnalysisResult> = {};
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

      // Dynamic LLM validation: analyze each finding to validate/enrich it
      const analyzer = new LLMAnalyzer(options.ai, options.privacy || {});
      const fileLoader = (file: string): string | null => {
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
      };
      aiValidatedFindings = Object.fromEntries(await analyzer.analyzeFindings(this.findings, fileLoader));

      // Apply LLM validation to findings (only enrich, never remove confirmed issues)
      for (const finding of this.findings) {
        const analysis = aiValidatedFindings[finding.id];
        if (!analysis) continue;
        if (analysis.confidenceAdjustment === 'upgrade' && finding.confidence !== 'HIGH') {
          finding.confidence = 'HIGH';
        }
        finding.aiAnalysis = {
          validated: analysis.validated,
          enrichedDescription: analysis.enrichedDescription,
          exploitScenario: analysis.exploitScenario,
          remediationSteps: analysis.remediationSteps,
          falsePositiveReason: analysis.falsePositiveReason,
          provider: options.ai.provider,
        };
      }
    }

    // Run plugin after-scan hooks
    this.findings = await this.pluginRegistry.runAfterScanHooks(this.findings, scanContext);

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
        aiAnalysis: aiUsed ? { enabled: true, report: aiReport, provider: options.ai!.provider, validatedFindings: Object.keys(aiValidatedFindings).length } : { enabled: false },
        evidenceExplanations: evidenceExplanations.map(e => ({
          findingId: e.findingId,
          dataFlowSteps: e.dataFlowSteps,
          sanitizationStatus: e.sanitizationStatus,
          confidenceReason: e.confidenceReason,
        })),
      },
      contextGraph: {
        nodes: contextGraph.nodes.map(n => ({ id: n.id, type: n.type, label: n.label })),
        edges: contextGraph.edges.map(e => ({ from: e.from, to: e.to, label: e.label, type: e.type })),
        chainCount: contextGraph.chains.length,
      },
      riskPriorities: riskPriorities.map(rp => ({
        findingId: rp.findingId,
        priority: rp.priority,
        score: rp.score,
        reasoning: rp.reasoning,
      })),
      endpoints: this.extractEndpoints(scanContext),
      dependencyGraph: {
        rootCount: dependencyGraph.roots.length,
        vulnerableCount: dependencyGraph.vulnerablePaths.length,
        vulnerablePaths: dependencyGraph.vulnerablePaths.map(vp => ({
          path: vp.path,
          findingId: vp.findingId,
          severity: vp.severity,
        })),
      },
    };
  }

  private extractEndpoints(context: ScanContext): Array<{ method: string; path: string; file: string; hasAuth: boolean; hasAuthz: boolean; hasValidation: boolean }> {
    const endpoints: Array<{ method: string; path: string; file: string; hasAuth: boolean; hasAuthz: boolean; hasValidation: boolean }> = [];
    for (const [key, value] of context.fileContents.entries()) {
      if (key.startsWith('__endpoints:')) {
        const file = key.replace('__endpoints:', '');
        for (const line of value.split('\n')) {
          if (!line.trim()) continue;
          const [method, ...pathParts] = line.split(' ');
          endpoints.push({
            method,
            path: pathParts.join(' '),
            file,
            hasAuth: false,
            hasAuthz: false,
            hasValidation: false,
          });
        }
      }
    }
    return endpoints;
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
      'api-discovery': ['api-discovery'],
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

  getPluginRegistry(): PluginRegistry {
    return this.pluginRegistry;
  }
}
