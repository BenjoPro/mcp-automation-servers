import os, subprocess, json
import httpx
from mcp.server.fastmcp import FastMCP
from typing import Optional

NEO4J_URI = "bolt://neo4j:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = os.environ.get("NEO4J_PASSWORD", "awsmcp2024")

def register(mcp: FastMCP):

    @mcp.tool()
    async def cartography_sync(regions: Optional[list] = None) -> str:
        """Build a Neo4j graph of the entire AWS environment using Cartography."""
        cmd = ["cartography","--neo4j-uri",NEO4J_URI,"--neo4j-user",NEO4J_USER,"--neo4j-password-env-var","NEO4J_PASS","--aws-sync-all-profiles"]
        env = {**os.environ, "NEO4J_PASS": NEO4J_PASS}
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600, env=env)
        except subprocess.TimeoutExpired:
            return "Cartography timed out."
        except FileNotFoundError:
            return "cartography not found."
        return f"Cartography sync complete.\nNeo4j Browser: http://localhost:7474\n\n{(result.stdout+result.stderr)[-2000:]}"

    @mcp.tool()
    async def cartography_query(cypher_query: str, limit: int = 50) -> str:
        """Run a Cypher query against the Cartography Neo4j graph.
        Example: MATCH (b:S3Bucket) RETURN b.name, b.region LIMIT 50"""
        url = "http://neo4j:7474/db/neo4j/tx/commit"
        payload = {"statements": [{"statement": cypher_query if "LIMIT" in cypher_query.upper() else cypher_query + f" LIMIT {limit}", "resultDataContents": ["row"]}]}
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(url, json=payload, auth=(NEO4J_USER, NEO4J_PASS), timeout=30)
            data = resp.json()
            errors = data.get("errors",[])
            if errors:
                return f"Cypher error: {errors[0]['message']}"
            results = data.get("results",[{}])[0]
            cols = results.get("columns",[])
            rows = results.get("data",[])
            if not rows:
                return "No results."
            output = [" | ".join(cols), "-"*60]
            for row in rows:
                output.append(" | ".join(str(v)[:80] for v in row.get("row",[])))
            return f"{len(rows)} row(s)\n\n" + "\n".join(output)
        except Exception as e:
            return f"Neo4j error: {e}"

    @mcp.tool()
    async def find_privilege_escalation_paths() -> str:
        """Run pre-built Cartography queries to find IAM privilege escalation paths."""
        queries = [
            {"name": "Users who can assume admin roles",
             "cypher": "MATCH (u:AWSUser)-[:STS_ASSUME_ROLE_ALLOW]->(r:AWSRole) WHERE r.name CONTAINS 'Admin' RETURN u.name as user, r.name as role LIMIT 25"},
            {"name": "Policies with wildcard actions",
             "cypher": "MATCH (p:AWSPolicy)-[:STATEMENT]->(s:AWSPolicyStatement) WHERE s.action CONTAINS '*' RETURN p.name as policy, s.action LIMIT 25"},
            {"name": "Cross-account role trusts",
             "cypher": "MATCH (r:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(p) WHERE r.account_id <> p.account_id RETURN r.name as role, p.name as trusted LIMIT 20"},
        ]
        url = "http://neo4j:7474/db/neo4j/tx/commit"
        output_parts = []
        async with httpx.AsyncClient() as client:
            for q in queries:
                try:
                    resp = await client.post(url, json={"statements":[{"statement":q["cypher"],"resultDataContents":["row"]}]}, auth=(NEO4J_USER,NEO4J_PASS), timeout=30)
                    data = resp.json()
                    rows = data.get("results",[{}])[0].get("data",[])
                    cols = data.get("results",[{}])[0].get("columns",[])
                    output_parts.append(f"\n{'='*50}\n{q['name']} ({len(rows)} results)\n{'-'*50}")
                    for row in rows[:10]:
                        output_parts.append(str(dict(zip(cols, row.get("row",[])))))
                except Exception as e:
                    output_parts.append(f"Error: {e}")
        return "\n".join(output_parts)
