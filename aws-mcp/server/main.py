from mcp.server.fastmcp import FastMCP
from server.tools import passive, credentials, iam, enumeration, cartography, reporting

mcp = FastMCP(
    name="AWS-MCP",
    description="AWS security enumeration server.",
)

passive.register(mcp)
credentials.register(mcp)
iam.register(mcp)
enumeration.register(mcp)
cartography.register(mcp)
reporting.register(mcp)

if __name__ == "__main__":
    mcp.run(transport="stdio")
