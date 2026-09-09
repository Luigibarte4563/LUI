import * as fs from 'fs';
import * as path from 'path';
import { ProjectProfile } from '../models/ProjectProfile';
import { TechnologyProfile } from '../models/ScanResult';
import { TechnologyDetector } from './TechnologyDetector';
import { getAllFiles, fileExists, readFileSafe } from '../utils/fileUtils';

export class ProjectDiscovery {
  private rootPath: string;
  private excludes: string[];

  constructor(rootPath: string, excludes: string[] = []) {
    this.rootPath = path.resolve(rootPath);
    this.excludes = excludes;
  }

  async discover(): Promise<ProjectProfile> {
    const projectName = this.getProjectName();
    const technology = await this.detectTechnology();
    const allFiles = getAllFiles(this.rootPath, undefined, this.excludes);
    const sourceFiles = this.filterSourceFiles(allFiles);
    const configFiles = this.filterConfigFiles(allFiles);
    const infrastructureFiles = this.filterInfrastructureFiles(allFiles);
    const sensitiveFiles = this.filterSensitiveFiles(allFiles);
    const totalSize = this.getTotalSize(allFiles);

    return {
      rootPath: this.rootPath,
      projectName,
      technology,
      hasPackageJson: fileExists(path.join(this.rootPath, 'package.json')),
      hasDockerfile: fileExists(path.join(this.rootPath, 'Dockerfile')),
      hasDockerCompose: fileExists(path.join(this.rootPath, 'docker-compose.yml')) || fileExists(path.join(this.rootPath, 'docker-compose.yaml')),
      hasCICD: this.hasCICD(),
      hasGit: fileExists(path.join(this.rootPath, '.git')),
      hasDotEnv: fileExists(path.join(this.rootPath, '.env')) || this.hasEnvFiles(),
      hasPython: technology.languages.includes('Python'),
      hasNode: technology.languages.includes('JavaScript') || technology.languages.includes('TypeScript'),
      hasPHP: technology.languages.includes('PHP'),
      hasJava: technology.languages.includes('Java'),
      hasGo: technology.languages.includes('Go'),
      hasRust: technology.languages.includes('Rust'),
      hasRuby: technology.languages.includes('Ruby'),
      hasDotNet: technology.languages.includes('C#'),
      fileCount: allFiles.length,
      sourceFiles,
      configFiles,
      infrastructureFiles,
      sensitiveFiles,
      totalSize,
    };
  }

  private getProjectName(): string {
    const pkgPath = path.join(this.rootPath, 'package.json');
    if (fileExists(pkgPath)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
        return pkg.name || path.basename(this.rootPath);
      } catch { /* ignore */ }
    }
    return path.basename(this.rootPath);
  }

  private async detectTechnology(): Promise<TechnologyProfile> {
    const detector = new TechnologyDetector(this.rootPath);
    return detector.detect();
  }

  private filterSourceFiles(files: string[]): string[] {
    const sourceExts = ['.js', '.ts', '.jsx', '.tsx', '.py', '.php', '.java', '.cs', '.go', '.rb', '.rs', '.vue', '.svelte', '.html', '.css', '.scss'];
    return files.filter(f => sourceExts.some(ext => f.endsWith(ext)));
  }

  private filterConfigFiles(files: string[]): string[] {
    const configPatterns = ['package.json', 'tsconfig.json', '.eslintrc', 'webpack.config', 'vite.config', 'next.config', 'nuxt.config', 'composer.json', 'requirements.txt', 'pyproject.toml', 'Cargo.toml', 'go.mod', 'pom.xml', 'build.gradle', '.babelrc', 'jest.config', '.prettierrc'];
    return files.filter(f => {
      const base = path.basename(f);
      return configPatterns.some(p => base.includes(p));
    });
  }

  private filterInfrastructureFiles(files: string[]): string[] {
    const infraExts = ['Dockerfile', 'docker-compose.yml', 'docker-compose.yaml', '.yml', '.yaml', '.tf', '.hcl', '.conf', '.ini'];
    return files.filter(f => {
      const base = path.basename(f);
      return infraExts.some(ext => base === ext || base.endsWith(ext)) ||
        f.includes('.github/workflows') || f.includes('.gitlab-ci');
    });
  }

  private filterSensitiveFiles(files: string[]): string[] {
    const sensitive = ['.env', '.env.local', '.env.production', '.env.development', 'id_rsa', 'id_ed25519', '.pem', '.key', 'credentials', '.htpasswd'];
    return files.filter(f => {
      const base = path.basename(f);
      return sensitive.some(s => base === s || base.startsWith('.env') || base.endsWith('.pem') || base.endsWith('.key'));
    });
  }

  private hasCICD(): boolean {
    return fileExists(path.join(this.rootPath, '.github', 'workflows')) ||
      fileExists(path.join(this.rootPath, '.gitlab-ci.yml')) ||
      fileExists(path.join(this.rootPath, 'Jenkinsfile')) ||
      fileExists(path.join(this.rootPath, '.circleci'));
  }

  private hasEnvFiles(): boolean {
    try {
      const entries = fs.readdirSync(this.rootPath);
      return entries.some(e => e.startsWith('.env'));
    } catch {
      return false;
    }
  }

  private getTotalSize(files: string[]): number {
    let total = 0;
    for (const f of files) {
      try {
        total += fs.statSync(f).size;
      } catch { /* ignore */ }
    }
    return total;
  }
}
