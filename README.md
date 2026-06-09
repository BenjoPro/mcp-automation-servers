# MCP Automation Servers

A collection of MCP (Model Context Protocol) servers for automation, OSINT, and security research.

## Projects

| Project | Description |
|---------|-------------|
| `kali-mcp` | Kali Linux MCP server (Docker) |
| `kali-mcp-bash` | Kali bash MCP server |
| `mcp-docker-stack` | Full MCP Docker stack with agent manager |
| `osint-mcp-build` | OSINT MCP server (Node.js) |
| `scada-osint-mcp` | SCADA/ICS OSINT MCP server (Python) |
| `dark-web-scraper` | Dark web scraper MCP server |

## Usage

Each project is self-contained with its own Dockerfile / docker-compose.yml.

> ⚠️ Never commit `.env` files or secrets. Use `.env.example` as a template.
