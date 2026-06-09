import os, json, glob
from datetime import datetime
from mcp.server.fastmcp import FastMCP
from typing import Optional

def register(mcp: FastMCP):

    @mcp.tool()
    async def list_reports() -> str:
        """List all generated reports in /reports."""
        files = [f for f in glob.glob("/reports/**/*", recursive=True) if os.path.isfile(f)]
        if not files:
            return "No reports yet. Run a scan first."
        by_tool = {}
        for f in sorted(files):
            rel = f.replace("/reports/","")
            tool = rel.split("/")[0] if "/" in rel else "misc"
            by_tool.setdefault(tool,[]).append(f"{rel}  ({os.path.getsize(f):,} bytes)")
        lines = ["Reports in /reports:\n"]
        for tool, items in by_tool.items():
            lines.append(f"[{tool.upper()}]")
            lines.extend(f"  {i}" for i in items)
            lines.append("")
        return "\n".join(lines)

    @mcp.tool()
    async def read_report_summary(report_path: str, max_chars: int = 8000) -> str:
        """Read a report file. report_path is relative to /reports."""
        full = f"/reports/{report_path}" if not report_path.startswith("/") else report_path
        if not os.path.exists(full):
            return f"Not found: {full}\nUse list_reports() to see available files."
        with open(full,"r",errors="replace") as f:
            content = f.read(max_chars)
        return f"File: {full}  ({os.path.getsize(full):,} bytes)\n{'-'*50}\n{content}"

    @mcp.tool()
    async def generate_executive_summary(account_id: Optional[str] = None) -> str:
        """Aggregate all scan results and produce structured data for an executive summary."""
        summary = {"generated_at": datetime.utcnow().isoformat()+"Z", "account_id": account_id or os.environ.get("AWS_ACCOUNT_ID","unknown"), "findings": {}}
        prowler_files = glob.glob("/reports/prowler/*.json")
        if prowler_files:
            fails = []
            for pf in prowler_files:
                try:
                    with open(pf) as f:
                        data = json.load(f)
                    for item in data:
                        if isinstance(item,dict) and item.get("status") == "FAIL":
                            fails.append({"check": item.get("check_id"), "severity": item.get("severity"), "service": item.get("service_name"), "region": item.get("region")})
                except Exception:
                    pass
            summary["findings"]["prowler"] = {"fail_count": len(fails), "critical_high": [f for f in fails if f.get("severity") in ("critical","high")][:20]}
        truffle_files = glob.glob("/reports/trufflehog_*.json")
        if truffle_files:
            all_secrets = []
            for tf in truffle_files:
                try:
                    with open(tf) as f:
                        all_secrets.extend(json.load(f))
                except Exception:
                    pass
            verified = [s for s in all_secrets if s.get("verified")]
            summary["findings"]["trufflehog"] = {"total": len(all_secrets), "verified_active": len(verified)}
        cloudsploit_files = glob.glob("/reports/cloudsploit/*.json")
        if cloudsploit_files:
            try:
                with open(cloudsploit_files[0]) as f:
                    data = json.load(f)
                counts = {}
                for item in data:
                    s = item.get("status","unknown")
                    counts[s] = counts.get(s,0)+1
                summary["findings"]["cloudsploit"] = counts
            except Exception:
                pass
        return json.dumps(summary, indent=2, default=str)
