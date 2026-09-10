export interface MCPTool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  handler: (input: Record<string, unknown>) => Promise<unknown>;
}

export interface MCPServer {
  name: string;
  version: string;
  tools: MCPTool[];
}

export function createMCPServer(): MCPServer {
  return {
    name: 'lui-security',
    version: '0.1.0',
    tools: [
      {
        name: 'lui_scan',
        description: 'Scan a project for security vulnerabilities',
        inputSchema: {
          type: 'object',
          properties: {
            path: { type: 'string', description: 'Path to project root' },
            scanType: { type: 'string', enum: ['quick', 'standard', 'deep'] },
            category: { type: 'string' },
          },
          required: ['path'],
        },
        handler: async (input) => {
          return { status: 'implement', message: 'Use lui scan CLI command', input };
        },
      },
      {
        name: 'lui_explain',
        description: 'Explain a specific security finding',
        inputSchema: {
          type: 'object',
          properties: {
            findingId: { type: 'string', description: 'Finding ID (e.g., LUI-SEC-001)' },
          },
          required: ['findingId'],
        },
        handler: async (input) => {
          return { status: 'implement', message: 'Use lui explain CLI command', input };
        },
      },
      {
        name: 'lui_verify',
        description: 'Verify if a security fix was applied',
        inputSchema: {
          type: 'object',
          properties: {
            findingId: { type: 'string' },
            path: { type: 'string' },
          },
          required: ['findingId'],
        },
        handler: async (input) => {
          return { status: 'implement', message: 'Use lui verify CLI command', input };
        },
      },
      {
        name: 'lui_investigate',
        description: 'Investigate security incident indicators',
        inputSchema: {
          type: 'object',
          properties: {
            path: { type: 'string' },
          },
          required: ['path'],
        },
        handler: async (input) => {
          return { status: 'implement', message: 'Use lui investigate CLI command', input };
        },
      },
    ],
  };
}
