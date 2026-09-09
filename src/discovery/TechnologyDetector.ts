import * as fs from 'fs';
import * as path from 'path';
import { TechnologyProfile } from '../models/ScanResult';
import { fileExists, readFileSafe } from '../utils/fileUtils';

export class TechnologyDetector {
  private rootPath: string;

  constructor(rootPath: string) {
    this.rootPath = rootPath;
  }

  detect(): TechnologyProfile {
    const languages = this.detectLanguages();
    const frameworks = this.detectFrameworks();
    const databases = this.detectDatabases();
    const authMethods = this.detectAuthMethods();
    const deployment = this.detectDeployment();
    const frontend = this.detectFrontend();
    const backend = this.detectBackend();
    const infrastructure = this.detectInfrastructure();
    const packageManagers = this.detectPackageManagers();

    const raw: Record<string, string> = {};
    if (fileExists(path.join(this.rootPath, 'package.json'))) {
      try {
        const pkg = JSON.parse(fs.readFileSync(path.join(this.rootPath, 'package.json'), 'utf-8'));
        raw['package.json'] = pkg.name || 'unknown';
      } catch { /* ignore */ }
    }

    return { languages, frameworks, databases, authMethods, deployment, frontend, backend, infrastructure, packageManagers, raw };
  }

  private detectLanguages(): string[] {
    const langs: string[] = [];
    const hasFiles = (ext: string[]) => {
      const files = this.getFilesWithExtensions(ext);
      return files.length > 0;
    };

    if (hasFiles(['.js', '.mjs', '.cjs'])) langs.push('JavaScript');
    if (hasFiles(['.ts', '.mts', '.cts'])) langs.push('TypeScript');
    if (hasFiles(['.py'])) langs.push('Python');
    if (hasFiles(['.php'])) langs.push('PHP');
    if (hasFiles(['.java'])) langs.push('Java');
    if (hasFiles(['.cs'])) langs.push('C#');
    if (hasFiles(['.go'])) langs.push('Go');
    if (hasFiles(['.rb'])) langs.push('Ruby');
    if (hasFiles(['.rs'])) langs.push('Rust');
    if (hasFiles(['.swift'])) langs.push('Swift');
    if (hasFiles(['.kt'])) langs.push('Kotlin');

    if (langs.length === 0) {
      const htmlFiles = this.getFilesWithExtensions(['.html', '.htm']);
      if (htmlFiles.length > 0) langs.push('HTML');
    }

    return langs;
  }

  private detectFrameworks(): string[] {
    const frameworks: string[] = [];
    const pkg = this.readPackageJson();

    if (pkg) {
      const deps: Record<string, string> = { ...(pkg.dependencies as Record<string, string> || {}), ...(pkg.devDependencies as Record<string, string> || {}) };
      const depNames = Object.keys(deps);

      if (depNames.some(d => d === 'react' || d === 'react-dom')) frameworks.push('React');
      if (depNames.some(d => d === 'vue' || d === 'nuxt')) frameworks.push('Vue');
      if (depNames.some(d => d === '@angular/core')) frameworks.push('Angular');
      if (depNames.some(d => d === 'next')) frameworks.push('Next.js');
      if (depNames.some(d => d === 'nuxt' || d === '@nuxt/core')) frameworks.push('Nuxt');
      if (depNames.some(d => d === 'svelte' || d === '@sveltejs/kit')) frameworks.push('Svelte');
      if (depNames.some(d => d === 'vite' || d === '@vitejs/plugin-react')) frameworks.push('Vite');
      if (depNames.some(d => d === 'express')) frameworks.push('Express');
      if (depNames.some(d => d === 'fastify')) frameworks.push('Fastify');
      if (depNames.some(d => d === 'koa')) frameworks.push('Koa');
      if (depNames.some(d => d === 'nestjs' || d === '@nestjs/core')) frameworks.push('NestJS');
      if (depNames.some(d => d === 'hapi' || d === '@hapi/hapi')) frameworks.push('Hapi');
      if (depNames.some(d => d === 'meteor')) frameworks.push('Meteor');
      if (depNames.some(d => d === 'graphql' || d === 'apollo-server')) frameworks.push('GraphQL');
    }

    const pyFiles = this.getFilesWithExtensions(['.py']);
    if (pyFiles.length > 0) {
      const content = pyFiles.slice(0, 20).map(f => readFileSafe(f) || '').join('\n');
      if (content.includes('django') || content.includes('from django')) frameworks.push('Django');
      if (content.includes('flask') || content.includes('from flask')) frameworks.push('Flask');
      if (content.includes('fastapi') || content.includes('from fastapi')) frameworks.push('FastAPI');
    }

    const phpFiles = this.getFilesWithExtensions(['.php']);
    if (phpFiles.length > 0) {
      const content = phpFiles.slice(0, 20).map(f => readFileSafe(f) || '').join('\n');
      if (content.includes('laravel') || content.includes('Laravel')) frameworks.push('Laravel');
      if (content.includes('symfony') || content.includes('Symfony')) frameworks.push('Symfony');
    }

    if (fileExists(path.join(this.rootPath, 'pom.xml')) || fileExists(path.join(this.rootPath, 'build.gradle'))) {
      frameworks.push('Java');
    }

    return frameworks;
  }

  private detectDatabases(): string[] {
    const dbs: string[] = [];
    const allContent = this.getAllSourceContent();
    if (allContent.includes('mysql') || allContent.includes('MySQL')) dbs.push('MySQL');
    if (allContent.includes('postgresql') || allContent.includes('postgres')) dbs.push('PostgreSQL');
    if (allContent.includes('mongodb') || allContent.includes('MongoDB')) dbs.push('MongoDB');
    if (allContent.includes('sqlite') || allContent.includes('SQLite')) dbs.push('SQLite');
    if (allContent.includes('redis') || allContent.includes('Redis')) dbs.push('Redis');
    if (allContent.includes('mssql') || allContent.includes('MSSQL')) dbs.push('MSSQL');
    return dbs;
  }

  private detectAuthMethods(): string[] {
    const methods: string[] = [];
    const allContent = this.getAllSourceContent();
    if (allContent.includes('jwt') || allContent.includes('JWT') || allContent.includes('jsonwebtoken')) methods.push('JWT');
    if (allContent.includes('passport') || allContent.includes('Passport')) methods.push('Passport');
    if (allContent.includes('oauth') || allContent.includes('OAuth')) methods.push('OAuth');
    if (allContent.includes('session') && (allContent.includes('express-session') || allContent.includes('cookie-session'))) methods.push('Session');
    if (allContent.includes('bcrypt') || allContent.includes('argon2')) methods.push('Password Hashing');
    if (allContent.includes('firebase') && allContent.includes('auth')) methods.push('Firebase Auth');
    if (allContent.includes('supabase')) methods.push('Supabase Auth');
    return methods;
  }

  private detectDeployment(): string[] {
    const deploy: string[] = [];
    if (fileExists(path.join(this.rootPath, 'Dockerfile'))) deploy.push('Docker');
    if (fileExists(path.join(this.rootPath, 'docker-compose.yml')) || fileExists(path.join(this.rootPath, 'docker-compose.yaml'))) deploy.push('Docker Compose');
    if (this.rootPath.includes('.github') || fileExists(path.join(this.rootPath, '.github', 'workflows'))) deploy.push('GitHub Actions');
    if (fileExists(path.join(this.rootPath, '.gitlab-ci.yml'))) deploy.push('GitLab CI');
    if (fileExists(path.join(this.rootPath, 'Jenkinsfile'))) deploy.push('Jenkins');
    const allContent = this.getAllSourceContent();
    if (allContent.includes('kubernetes') || allContent.includes('kubectl')) deploy.push('Kubernetes');
    if (fileExists(path.join(this.rootPath, 'serverless.yml')) || fileExists(path.join(this.rootPath, 'serverless.yaml'))) deploy.push('Serverless');
    return deploy;
  }

  private detectFrontend(): string[] {
    const fe: string[] = [];
    const pkg = this.readPackageJson();
    if (pkg) {
      const deps: Record<string, string> = { ...(pkg.dependencies as Record<string, string> || {}), ...(pkg.devDependencies as Record<string, string> || {}) };
      const depNames = Object.keys(deps);
      if (depNames.some(d => d === 'react' || d === 'react-dom')) fe.push('React');
      if (depNames.some(d => d === 'vue')) fe.push('Vue');
      if (depNames.some(d => d === '@angular/core')) fe.push('Angular');
      if (depNames.some(d => d === 'svelte' || d === '@sveltejs/kit')) fe.push('Svelte');
      if (depNames.some(d => d === 'next')) fe.push('Next.js');
      if (depNames.some(d => d === 'nuxt')) fe.push('Nuxt');
    }
    return fe;
  }

  private detectBackend(): string[] {
    const be: string[] = [];
    const pkg = this.readPackageJson();
    if (pkg) {
      const deps: Record<string, string> = { ...(pkg.dependencies as Record<string, string> || {}), ...(pkg.devDependencies as Record<string, string> || {}) };
      const depNames = Object.keys(deps);
      if (depNames.some(d => d === 'express')) be.push('Express');
      if (depNames.some(d => d === 'fastify')) be.push('Fastify');
      if (depNames.some(d => d === 'koa')) be.push('Koa');
      if (depNames.some(d => d === '@nestjs/core')) be.push('NestJS');
    }
    if (this.getFilesWithExtensions(['.php']).length > 0) be.push('PHP');
    if (this.getFilesWithExtensions(['.py']).length > 0) be.push('Python');
    if (this.getFilesWithExtensions(['.java']).length > 0) be.push('Java');
    if (this.getFilesWithExtensions(['.go']).length > 0) be.push('Go');
    if (this.getFilesWithExtensions(['.rb']).length > 0) be.push('Ruby');
    if (this.getFilesWithExtensions(['.cs']).length > 0) be.push('.NET');
    return be;
  }

  private detectInfrastructure(): string[] {
    const infra: string[] = [];
    if (fileExists(path.join(this.rootPath, 'Dockerfile'))) infra.push('Docker');
    if (fileExists(path.join(this.rootPath, 'docker-compose.yml')) || fileExists(path.join(this.rootPath, 'docker-compose.yaml'))) infra.push('Docker Compose');
    if (fileExists(path.join(this.rootPath, '.github', 'workflows'))) infra.push('GitHub Actions');
    if (fileExists(path.join(this.rootPath, '.gitlab-ci.yml'))) infra.push('GitLab CI');
    if (fileExists(path.join(this.rootPath, 'nginx.conf'))) infra.push('Nginx');
    if (fileExists(path.join(this.rootPath, 'terraform.tf')) || fileExists(path.join(this.rootPath, '*.tf'))) infra.push('Terraform');
    return infra;
  }

  private detectPackageManagers(): string[] {
    const pm: string[] = [];
    if (fileExists(path.join(this.rootPath, 'package-lock.json')) || fileExists(path.join(this.rootPath, 'package.json'))) pm.push('npm');
    if (fileExists(path.join(this.rootPath, 'yarn.lock'))) pm.push('yarn');
    if (fileExists(path.join(this.rootPath, 'pnpm-lock.yaml'))) pm.push('pnpm');
    if (fileExists(path.join(this.rootPath, 'composer.json'))) pm.push('composer');
    if (fileExists(path.join(this.rootPath, 'requirements.txt')) || fileExists(path.join(this.rootPath, 'Pipfile.lock'))) pm.push('pip');
    if (fileExists(path.join(this.rootPath, 'pyproject.toml'))) pm.push('pip');
    if (fileExists(path.join(this.rootPath, 'Cargo.toml'))) pm.push('cargo');
    if (fileExists(path.join(this.rootPath, 'go.mod'))) pm.push('go mod');
    if (fileExists(path.join(this.rootPath, 'Gemfile'))) pm.push('bundler');
    return [...new Set(pm)];
  }

  private readPackageJson(): Record<string, unknown> | null {
    const pkgPath = path.join(this.rootPath, 'package.json');
    try {
      return JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
    } catch {
      return null;
    }
  }

  private getFilesWithExtensions(extensions: string[]): string[] {
    const files: string[] = [];
    try {
      const entries = fs.readdirSync(this.rootPath, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'vendor') continue;
        if (entry.isFile() && extensions.some(ext => entry.name.endsWith(ext))) {
          files.push(path.join(this.rootPath, entry.name));
        }
        if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules' && entry.name !== 'vendor') {
          files.push(...this.getFilesWithExtensionsInDir(path.join(this.rootPath, entry.name), extensions));
        }
      }
    } catch { /* ignore */ }
    return files;
  }

  private getFilesWithExtensionsInDir(dir: string, extensions: string[]): string[] {
    const files: string[] = [];
    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'vendor') continue;
        if (entry.isFile() && extensions.some(ext => entry.name.endsWith(ext))) {
          files.push(path.join(dir, entry.name));
        }
        if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules' && entry.name !== 'vendor') {
          files.push(...this.getFilesWithExtensionsInDir(path.join(dir, entry.name), extensions));
        }
      }
    } catch { /* ignore */ }
    return files;
  }

  private getAllSourceContent(): string {
    const files = this.getFilesWithExtensions(['.js', '.ts', '.jsx', '.tsx', '.py', '.php', '.java', '.cs', '.go', '.rb', '.rs', '.vue', '.svelte']);
    let content = '';
    for (const f of files.slice(0, 100)) {
      const c = readFileSafe(f);
      if (c) content += c + '\n';
    }
    return content;
  }
}
