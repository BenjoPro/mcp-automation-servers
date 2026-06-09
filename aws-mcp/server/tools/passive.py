import os, subprocess, json
import httpx
from mcp.server.fastmcp import FastMCP
from typing import Optional

def register(mcp: FastMCP):

    @mcp.tool()
    async def google_dork(query: str, num_results: int = 20, site_filter: Optional[str] = None) -> str:
        """Run a Google dork query to find exposed AWS assets or keys."""
        full_query = f"site:{site_filter} {query}" if site_filter else query
        api_key = os.environ.get("GOOGLE_API_KEY")
        cse_id = os.environ.get("GOOGLE_CSE_ID")
        if not api_key or not cse_id:
            return f"GOOGLE_API_KEY / GOOGLE_CSE_ID not set. Query: {full_query}"
        params = {"key": api_key, "cx": cse_id, "q": full_query, "num": min(num_results, 10)}
        async with httpx.AsyncClient() as client:
            resp = await client.get("https://www.googleapis.com/customsearch/v1", params=params, timeout=15)
        items = resp.json().get("items", [])
        results = [{"title": i.get("title"), "link": i.get("link"), "snippet": i.get("snippet")} for i in items]
        return json.dumps(results, indent=2) if results else "No results."

    @mcp.tool()
    async def ghdb_search(category: str = "Cloud Storage", keyword: Optional[str] = None) -> str:
        """Search the Google Hacking Database for AWS-related dorks."""
        ghdb = {
            "Cloud Storage": [
                {"dork": "site:s3.amazonaws.com filetype:env", "desc": "Exposed .env files in S3"},
                {"dork": "site:s3.amazonaws.com password", "desc": "Password strings in S3"},
                {"dork": "inurl:s3.amazonaws.com ext:pem", "desc": "Private keys in S3"},
            ],
            "Files Containing Passwords": [
                {"dork": "AKIA site:github.com", "desc": "AWS access key IDs on GitHub"},
                {"dork": "aws_secret_access_key site:github.com", "desc": "AWS secret keys on GitHub"},
                {"dork": "filetype:yaml aws_access_key_id", "desc": "Keys in YAML configs"},
                {"dork": "filetype:tf aws_access_key", "desc": "Keys in Terraform files"},
            ],
            "Sensitive Directories": [
                {"dork": "intitle:Index of .aws", "desc": "Exposed .aws directories"},
            ],
        }
        selected = ghdb.get(category, [])
        if keyword:
            selected = [d for d in selected if keyword.lower() in d["dork"].lower()]
        if not selected:
            return f"No dorks found for category: {category}"
        lines = [f"[{category}]", "-"*40]
        for item in selected:
            dork = item["dork"]
            desc = item["desc"]
            lines.append(f"Dork: {dork}")
            lines.append(f"Desc: {desc}")
            lines.append("")
        return "\n".join(lines)

    @mcp.tool()
    async def grayhat_warfare_search(keyword: str, bucket_type: str = "s3", limit: int = 50) -> str:
        """Search Grayhat Warfare for open cloud buckets. Requires GRAYHAT_API_KEY."""
        api_key = os.environ.get("GRAYHAT_API_KEY")
        if not api_key:
            return "GRAYHAT_API_KEY not set."
        headers = {"Authorization": f"Bearer {api_key}"}
        params = {"keywords": keyword, "type": bucket_type, "limit": limit}
        async with httpx.AsyncClient() as client:
            resp = await client.get("https://buckets.grayhatwarfare.com/api/v2/buckets", headers=headers, params=params, timeout=20)
        if resp.status_code != 200:
            return f"API error {resp.status_code}: {resp.text}"
        buckets = resp.json().get("buckets", [])
        if not buckets:
            return f"No open buckets found for: {keyword}"
        return json.dumps([{"name": b.get("bucket"), "objects": b.get("objects"), "url": b.get("url")} for b in buckets], indent=2)

    @mcp.tool()
    async def cloudbrute_scan(domain: str, keyword: str, cloud_provider: str = "aws", threads: int = 80) -> str:
        """Run CloudBrute to discover exposed cloud assets for a target domain."""
        safe_domain = domain.replace(".", "_")
        output_file = f"/reports/cloudbrute_{safe_domain}.txt"
        cmd = ["cloudbrute", "-d", domain, "-k", keyword, "-t", str(threads), "-p", cloud_provider, "-o", output_file]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if os.path.exists(output_file):
                with open(output_file) as f:
                    return f"CloudBrute complete.\n\n{f.read()}"
            return f"CloudBrute output:\n{result.stdout[:3000]}"
        except subprocess.TimeoutExpired:
            return "CloudBrute timed out."
        except FileNotFoundError:
            return "cloudbrute binary not found."
