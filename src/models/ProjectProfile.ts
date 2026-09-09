import { TechnologyProfile } from './ScanResult';

export interface ProjectProfile {
  rootPath: string;
  projectName: string;
  technology: TechnologyProfile;
  hasPackageJson: boolean;
  hasDockerfile: boolean;
  hasDockerCompose: boolean;
  hasCICD: boolean;
  hasGit: boolean;
  hasDotEnv: boolean;
  hasPython: boolean;
  hasNode: boolean;
  hasPHP: boolean;
  hasJava: boolean;
  hasGo: boolean;
  hasRust: boolean;
  hasRuby: boolean;
  hasDotNet: boolean;
  fileCount: number;
  sourceFiles: string[];
  configFiles: string[];
  infrastructureFiles: string[];
  sensitiveFiles: string[];
  totalSize: number;
}
