const { Server } = require('@modelcontextprotocol/sdk/server/index.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const { CallToolRequestSchema, ListToolsRequestSchema } = require('@modelcontextprotocol/sdk/types.js');
const { execSync } = require('child_process');

const server = new Server({ name: 'kali-bash', version: '1.0.0' }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: 'run_command',
    description: 'Run a bash command on Kali Linux',
    inputSchema: {
      type: 'object',
      properties: { command: { type: 'string', description: 'The bash command to run' } },
      required: ['command']
    }
  }]
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  if (request.params.name === 'run_command') {
    const command = request.params.arguments.command;
    try {
      const output = execSync(command, { timeout: 30000 }).toString();
      return { content: [{ type: 'text', text: output }] };
    } catch (error) {
      return { content: [{ type: 'text', text: error.message }] };
    }
  }
});

const transport = new StdioServerTransport();
server.connect(transport);
