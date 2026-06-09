import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import axios from "axios";

const server = new Server(
  { name: "mcp-docker-server", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "get_current_ip",
      description: "מחזיר את ה-IP הנוכחי דרך ה-VPN",
      inputSchema: { type: "object", properties: {} },
    },
    {
      name: "get_current_agent",
      description: "מחזיר את ה-User-Agent הנוכחי",
      inputSchema: { type: "object", properties: {} },
    },
    {
      name: "fetch_url",
      description: "מבצע בקשת HTTP דרך ה-VPN עם Agent רנדומלי",
      inputSchema: {
        type: "object",
        properties: {
          url: { type: "string", description: "ה-URL לגשת אליו" },
        },
        required: ["url"],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  if (name === "get_current_ip") {
    const res = await axios.get("https://api.ipify.org?format=json");
    return { content: [{ type: "text", text: `IP נוכחי: ${res.data.ip}` }] };
  }

  if (name === "get_current_agent") {
    const res = await axios.get("http://localhost:3001/current-agent");
    return { content: [{ type: "text", text: res.data.agent }] };
  }

  if (name === "fetch_url") {
    const agentRes = await axios.get("http://localhost:3001/current-agent");
    const userAgent = agentRes.data.agent;
    const res = await axios.get(args.url, {
      headers: { "User-Agent": userAgent },
    });
    return {
      content: [{ type: "text", text: res.data.toString().slice(0, 2000) }],
    };
  }

  throw new Error(`כלי לא מוכר: ${name}`);
});

const transport = new StdioServerTransport();
await server.connect(transport);
console.error("MCP Server מוכן ✓");
