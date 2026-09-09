import { Finding } from '../models/Finding';

export interface DataFlow {
  source: string;
  sink: string;
  file: string;
  sinkLine: number;
  variables: string[];
  confidence: 'HIGH' | 'MEDIUM';
}

export interface SinkRule {
  name: string;
  label: string;
  regex: RegExp;
}

export const SINK_RULES: SinkRule[] = [
  { name: 'SQL Injection', label: 'SQL query', regex: /(?:\.query|\.execute|\.exec|\.run|executemany)\s*\(|SELECT\s+[^;]*\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|MariaDB|sqlalchemy/i },
  { name: 'Command Injection', label: 'system command', regex: /(?:exec|spawn|execSync|execFile|execFileSync|system|popen|passthru|child_process)\s*\(/i },
  { name: 'Reflected XSS', label: 'untrusted HTML output', regex: /(?:innerHTML|outerHTML|document\.write|insertAdjacentHTML|render_template_string|->render\s*\(|res\.(?:send|write|render)\s*\(|<%\s*=|\$\{)/i },
  { name: 'Path Traversal', label: 'file system access', regex: /(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|readFileAsString|Path\.join|cwd\()/i },
  { name: 'Insecure Deserialization', label: 'deserialization call', regex: /(?:pickle\.loads?|yaml\.(?:load|safe_load|unsafe_load)|unserialize|node\-serialize|pserialize\.unpickle|JSON\.parse\s*\(\s*req)/i },
  { name: 'Insecure LDAP Binding', label: 'LDAP filter construction', regex: /(?:ldapsearch|simpleBind|add\(|modify\(|remove\()/i },
];

const SOURCE_ALTERNATION = [
  /req\.(?:query|params|body|cookies|headers)[.\w$]*/,
  /request\.(?:query|params|body|cookies|headers|form|args|values|json)[.\w$]*/,
  /ctx\.(?:query|params|body)[.\w$]*/,
  /(?:event|rawEvent)\.(?:queryStringParameters|body|headers)[.\w$]*/,
  /getParameter(?:Values)?\([^)]*\)/,
  /\$_GET\[|baseQueryString\[|\$_POST\[|\$_REQUEST\[|\$_COOKIE\[/,
  /\$this->input->(?:get|post|request|get_post)\(/,
  /request\.(?:args|form|values|json|query_string)/,
  /request\.get_data\(/,
].map(r => r.source).join('|');

const SOURCE_REGEX = new RegExp(SOURCE_ALTERNATION, 'i');

const VARIABLE_ASSIGN = new RegExp(`(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)\\s*=\\s*(${SOURCE_ALTERNATION})`, 'i');
const DESTRUCTURE_ASSIGN = new RegExp(`(?:const|let|var)\\s*\\{\\s*([A-Za-z_$][\\w$]*\\s*[,}]|[\\w$,\\s]+)\\}\\s*=\\s*(${SOURCE_ALTERNATION})`, 'i');

const WINDOW_LINES = 40;

export function collectTaintedVariables(content: string): string[] {
  const variables = new Set<string>();

  let m: RegExpExecArray | null;
  const assignRegex = new RegExp(VARIABLE_ASSIGN.source, 'gi');
  while ((m = assignRegex.exec(content)) !== null) {
    variables.add(m[1]);
  }

  const destructureRegex = new RegExp(DESTRUCTURE_ASSIGN.source, 'gi');
  while ((m = destructureRegex.exec(content)) !== null) {
    const names = m[1].split(',').map(s => s.trim()).filter(n => /^[A-Za-z_$][\w$]*$/.test(n));
    for (const name of names) variables.add(name);
  }

  return Array.from(variables);
}

function windowContains(text: string, sinkIndex: number, pattern: RegExp, variables: string[]): boolean {
  const lines = text.split('\n');
  const start = Math.max(0, sinkIndex - WINDOW_LINES);
  const end = Math.min(lines.length, sinkIndex + WINDOW_LINES + 1);
  const windowText = lines.slice(start, end).join('\n');

  if (pattern.test(windowText)) return true;
  for (const variable of variables) {
    if (new RegExp(`\\b${variable}\\b`, 'i').test(windowText)) return true;
  }
  return false;
}

export function matchSink(line: string): SinkRule | null {
  for (const rule of SINK_RULES) {
    if (rule.regex.test(line)) return rule;
  }
  return null;
}

export function analyzeDataFlows(
  findings: Finding[],
  rootPath: string,
  getContent: (file: string) => string | null
): DataFlow[] {
  const flows: DataFlow[] = [];
  const sinkFindings = findings.filter(f =>
    f.affectedFiles.length > 0 &&
    typeof f.affectedFiles[0].line === 'number' &&
    (f.title.includes('njection') || f.title.includes('XSS') || f.title.includes('Path Traversal') ||
     f.title.includes('Injection') || f.category === 'XSS' || f.category === 'Deserialization')
  );

  for (const finding of sinkFindings) {
    const location = finding.affectedFiles[0];
    const content = getContent(location.file);
    if (!content) continue;

    const sinkIndex = (location.line || 1) - 1;
    const sinkLine = content.split('\n')[sinkIndex] || '';
    const sink = matchSink(sinkLine);

    const variables = collectTaintedVariables(content);

    if (!sink) continue;

    const directOnLine = SOURCE_REGEX.test(sinkLine);
    const taintedInScope = windowContains(content, sinkIndex, SOURCE_REGEX, variables);

    if (directOnLine || taintedInScope) {
      flows.push({
        source: 'HTTP request input',
        sink: sink.label,
        file: location.file,
        sinkLine: location.line || 1,
        variables: variables.length > 0 ? variables : [],
        confidence: directOnLine ? 'HIGH' : 'MEDIUM',
      });
    }
  }

  return flows;
}

export function applyTaintConfidence(findings: Finding[], flows: DataFlow[]): Finding[] {
  const weight = (c: string): number => (c === 'HIGH' ? 3 : c === 'MEDIUM' ? 2 : 1);

  return findings.map(f => {
    if (!flows || flows.length === 0) return f;
    const location = f.affectedFiles[0];
    if (!location || typeof location.line !== 'number') return f;

    const flow = flows.find(fl =>
      fl.file === location.file && Math.abs(fl.sinkLine - (location.line || 0)) <= 2
    );
    if (!flow) return f;

    const flowConfidence = flow.confidence === 'HIGH' ? 'HIGH' as const : 'MEDIUM' as const;
    const confidence = weight(flowConfidence) >= weight(f.confidence) ? flowConfidence : f.confidence;

    return {
      ...f,
      type: 'confirmed' as const,
      confidence,
      evidence: [
        ...f.evidence,
        `Data flow confirmed: ${flow.source} -> ${flow.sink} (line ${flow.sinkLine})`,
      ],
    };
  });
}