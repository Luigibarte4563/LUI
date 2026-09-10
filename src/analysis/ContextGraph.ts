import { Finding } from '../models/Finding';

export interface GraphNode {
  id: string;
  type: 'input' | 'process' | 'storage' | 'output' | 'external' | 'auth' | 'endpoint';
  label: string;
  file?: string;
  line?: number;
  metadata?: Record<string, string>;
}

export interface GraphEdge {
  from: string;
  to: string;
  label: string;
  type: 'data' | 'auth' | 'control' | 'dependency';
  findingIds?: string[];
}

export interface SecurityContextGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  chains: GraphChain[];
}

export interface GraphChain {
  id: string;
  title: string;
  description: string;
  steps: string[];
  riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  findingIds: string[];
}

const INPUT_PATTERNS: RegExp[] = [
  /req\.(?:query|params|body|cookies|headers)/i,
  /request\.(?:form|args|json|data)/i,
  /\$_GET|\$_POST|\$_REQUEST/i,
];

const SINK_PATTERNS: RegExp[] = [
  /(?:\.query|\.execute|\.run)\s*\(/i,
  /(?:exec|spawn|execSync)\s*\(/i,
  /(?:res\.(?:send|write|render))/i,
  /(?:readFile|writeFile)/i,
];

const STORAGE_PATTERNS: RegExp[] = [
  /(?:mysql|pg|mongo|sqlite|redis)(?:\.connect|\.createConnection|\.Pool)/i,
  /(?:createPool|createClient|\.collection)/i,
];

const AUTH_PATTERNS: RegExp[] = [
  /(?:jwt\.sign|jwt\.verify|bcrypt|password|login|register|token)/i,
  /(?:session|cookie|oauth|passport)/i,
];

export function buildContextGraph(
  findings: Finding[],
  getContent: (file: string) => string | null
): SecurityContextGraph {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const nodeMap = new Map<string, GraphNode>();

  const addNode = (node: GraphNode): void => {
    if (!nodeMap.has(node.id)) {
      nodeMap.set(node.id, node);
      nodes.push(node);
    }
  };

  const addEdge = (edge: GraphEdge): void => {
    const exists = edges.some(e => e.from === edge.from && e.to === edge.to && e.label === edge.label);
    if (!exists) edges.push(edge);
  };

  const endpointFiles = new Map<string, string[]>();

  for (const finding of findings) {
    for (const loc of finding.affectedFiles) {
      const content = getContent(loc.file);
      if (!content) continue;

      const fileLines = content.split('\n');

      for (let i = 0; i < fileLines.length; i++) {
        const line = fileLines[i];

        for (const pattern of INPUT_PATTERNS) {
          if (pattern.test(line)) {
            const nodeId = `input:${loc.file}:${i + 1}`;
            addNode({
              id: nodeId,
              type: 'input',
              label: extractVariableName(line) || 'User Input',
              file: loc.file,
              line: i + 1,
            });
          }
        }

        for (const pattern of SINK_PATTERNS) {
          if (pattern.test(line)) {
            const nodeId = `sink:${loc.file}:${i + 1}`;
            addNode({
              id: nodeId,
              type: 'output',
              label: extractSinkLabel(line),
              file: loc.file,
              line: i + 1,
            });
          }
        }

        for (const pattern of STORAGE_PATTERNS) {
          if (pattern.test(line)) {
            const nodeId = `storage:${loc.file}:${i + 1}`;
            addNode({
              id: nodeId,
              type: 'storage',
              label: extractStorageLabel(line),
              file: loc.file,
              line: i + 1,
            });
          }
        }

        for (const pattern of AUTH_PATTERNS) {
          if (pattern.test(line)) {
            const nodeId = `auth:${loc.file}:${i + 1}`;
            addNode({
              id: nodeId,
              type: 'auth',
              label: extractAuthLabel(line),
              file: loc.file,
              line: i + 1,
            });
          }
        }
      }

      const routeMatch = content.match(/(?:app|router)\.(?:get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)/);
      if (routeMatch) {
        const endpointId = `endpoint:${loc.file}:${routeMatch[1]}`;
        addNode({
          id: endpointId,
          type: 'endpoint',
          label: routeMatch[1],
          file: loc.file,
        });
        if (!endpointFiles.has(loc.file)) endpointFiles.set(loc.file, []);
        endpointFiles.get(loc.file)!.push(endpointId);
      }
    }
  }

  for (const finding of findings) {
    if (finding.affectedFiles.length === 0) continue;
    const loc = finding.affectedFiles[0];

    const inputNodes = nodes.filter(n => n.type === 'input' && n.file === loc.file);
    const sinkNodes = nodes.filter(n => n.type === 'output' && n.file === loc.file);
    const storageNodes = nodes.filter(n => n.type === 'storage');
    const authNodes = nodes.filter(n => n.type === 'auth' && n.file === loc.file);

    for (const input of inputNodes) {
      for (const sink of sinkNodes) {
        addEdge({
          from: input.id,
          to: sink.id,
          label: finding.title,
          type: 'data',
          findingIds: [finding.id],
        });
      }
    }

    if (sinkNodes.length > 0 && storageNodes.length > 0) {
      addEdge({
        from: sinkNodes[0].id,
        to: storageNodes[0].id,
        label: 'writes to',
        type: 'data',
      });
    }

    for (const auth of authNodes) {
      for (const sink of sinkNodes) {
        addEdge({
          from: auth.id,
          to: sink.id,
          label: 'auth context',
          type: 'auth',
        });
      }
    }
  }

  const chains = identifyGraphChains(nodes, edges, findings);

  return { nodes, edges, chains };
}

function identifyGraphChains(
  nodes: GraphNode[],
  edges: GraphEdge[],
  findings: Finding[]
): GraphChain[] {
  const chains: GraphChain[] = [];

  const inputNodes = nodes.filter(n => n.type === 'input');
  for (const input of inputNodes) {
    const reachable = bfs(input.id, edges);
    const sinkReachable = reachable.filter(id => {
      const node = nodes.find(n => n.id === id);
      return node?.type === 'output' || node?.type === 'storage';
    });

    if (sinkReachable.length >= 2) {
      const involvedFindings = edges
        .filter(e => reachable.includes(e.to) && e.findingIds)
        .flatMap(e => e.findingIds!);

      chains.push({
        id: `chain-${chains.length + 1}`,
        title: `Data flows from ${input.label} to ${sinkReachable.length} sinks`,
        description: `User input at ${input.label} reaches multiple dangerous sinks, indicating a broad attack surface.`,
        steps: [input.id, ...sinkReachable],
        riskLevel: involvedFindings.some(id => {
          const f = findings.find(f => f.id === id);
          return f?.severity === 'CRITICAL' || f?.severity === 'HIGH';
        }) ? 'HIGH' : 'MEDIUM',
        findingIds: [...new Set(involvedFindings)],
      });
    }
  }

  return chains;
}

function bfs(startId: string, edges: GraphEdge[]): string[] {
  const visited = new Set<string>();
  const queue = [startId];
  visited.add(startId);

  while (queue.length > 0) {
    const current = queue.shift()!;
    for (const edge of edges) {
      if (edge.from === current && !visited.has(edge.to)) {
        visited.add(edge.to);
        queue.push(edge.to);
      }
    }
  }

  return Array.from(visited);
}

function extractVariableName(line: string): string {
  const match = line.match(/(?:const|let|var)\s+(\w+)/);
  if (match) return match[1];
  const paramMatch = line.match(/req\.(?:query|params|body)\.(\w+)/);
  if (paramMatch) return `req.${paramMatch[1]}`;
  return '';
}

function extractSinkLabel(line: string): string {
  if (/(?:\.query|\.execute|\.run)\s*\(/.test(line)) return 'Database Query';
  if (/(?:exec|spawn|execSync)\s*\(/.test(line)) return 'System Command';
  if (/(?:res\.(?:send|write|render))/.test(line)) return 'HTTP Response';
  if (/(?:readFile|writeFile)/.test(line)) return 'File Operation';
  return 'Dangerous Operation';
}

function extractStorageLabel(line: string): string {
  if (/mysql/i.test(line)) return 'MySQL';
  if (/pg|postgres/i.test(line)) return 'PostgreSQL';
  if (/mongo/i.test(line)) return 'MongoDB';
  if (/sqlite/i.test(line)) return 'SQLite';
  if (/redis/i.test(line)) return 'Redis';
  return 'Database';
}

function extractAuthLabel(line: string): string {
  if (/jwt/i.test(line)) return 'JWT';
  if (/bcrypt/i.test(line)) return 'Password Hash';
  if (/login/i.test(line)) return 'Login';
  if (/register/i.test(line)) return 'Registration';
  if (/session/i.test(line)) return 'Session';
  if (/oauth/i.test(line)) return 'OAuth';
  return 'Auth';
}

export function formatContextGraph(graph: SecurityContextGraph): string {
  const lines: string[] = [];

  const grouped = {
    input: graph.nodes.filter(n => n.type === 'input'),
    endpoint: graph.nodes.filter(n => n.type === 'endpoint'),
    auth: graph.nodes.filter(n => n.type === 'auth'),
    storage: graph.nodes.filter(n => n.type === 'storage'),
    output: graph.nodes.filter(n => n.type === 'output'),
  };

  for (const [type, nodes] of Object.entries(grouped)) {
    if (nodes.length === 0) continue;
    lines.push(`${type.toUpperCase()}`);
    for (const node of nodes) {
      const loc = node.file && node.line ? ` (${node.file}:${node.line})` : '';
      lines.push(`  ├── ${node.label}${loc}`);
    }
  }

  if (graph.chains.length > 0) {
    lines.push('');
    lines.push('DATA FLOW CHAINS');
    for (const chain of graph.chains) {
      lines.push(`  ${chain.riskLevel} ${chain.title}`);
      lines.push(`    ${chain.description}`);
    }
  }

  return lines.join('\n');
}
