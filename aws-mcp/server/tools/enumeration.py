import os, subprocess, json
import boto3
from botocore.exceptions import ClientError
from mcp.server.fastmcp import FastMCP
from typing import Optional

def register(mcp: FastMCP):

    @mcp.tool()
    async def prowler_scan(services: Optional[list] = None, compliance: str = "cis_aws_foundations_benchmark_2.0", output_format: str = "html", region: Optional[str] = None) -> str:
        """Run Prowler security assessment. compliance options: cis_aws_foundations_benchmark_2.0 / nist_800_53_revision_5 / pci_dss_3.2.1 / hipaa"""
        report_dir = "/reports/prowler"
        os.makedirs(report_dir, exist_ok=True)
        cmd = ["prowler","aws","--compliance",compliance,"--output-formats",output_format,"--output-directory",report_dir,"--ignore-exit-code-3"]
        if region:
            cmd += ["--region", region]
        if services:
            cmd += ["--services"] + services
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        except subprocess.TimeoutExpired:
            return "Prowler timed out."
        except FileNotFoundError:
            return "prowler not found."
        output = result.stdout + result.stderr
        summary = [l for l in output.splitlines() if any(k in l for k in ["PASS","FAIL","ERROR","total","Severity"])]
        return f"Prowler complete. Reports in {report_dir}\n\n" + "\n".join(summary[-40:])

    @mcp.tool()
    async def scoutsuite_scan(services: Optional[list] = None, regions: Optional[list] = None, report_name: str = "scoutsuite-report") -> str:
        """Run Scout Suite to enumerate and map the entire AWS environment."""
        report_dir = "/reports/scoutsuite"
        os.makedirs(report_dir, exist_ok=True)
        cmd = ["python3","/opt/tools/scoutsuite/scout.py","aws","--report-dir",report_dir,"--report-name",report_name,"--no-browser"]
        if services:
            cmd += ["--services"] + services
        if regions:
            cmd += ["--regions"] + regions
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=7200)
        except subprocess.TimeoutExpired:
            return "Scout Suite timed out."
        except FileNotFoundError:
            return "Scout Suite not found."
        return f"Scout Suite complete.\nHTML: {report_dir}/{report_name}.html\nJSON: {report_dir}/{report_name}.json\n\n{(result.stdout+result.stderr)[-2000:]}"

    @mcp.tool()
    async def cloudsploit_scan(report_name: str = "cloudsploit-report") -> str:
        """Run Cloudsploit to detect AWS misconfigurations across 200+ checks."""
        report_dir = "/reports/cloudsploit"
        os.makedirs(report_dir, exist_ok=True)
        json_out = f"{report_dir}/{report_name}.json"
        html_out = f"{report_dir}/{report_name}.html"
        config = f"""var AWSConfig = {{
  accessKeyId: process.env.AWS_ACCESS_KEY_ID || "",
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY || "",
  sessionToken: process.env.AWS_SESSION_TOKEN || "",
  region: process.env.AWS_DEFAULT_REGION || "us-east-1",
}};
module.exports = {{ AWS: AWSConfig }};"""
        with open("/opt/tools/cloudsploit/config.js","w") as f:
            f.write(config)
        try:
            result = subprocess.run(["node","index.js","--config","config.js","--json",json_out,"--html",html_out],
                capture_output=True, text=True, timeout=1800, cwd="/opt/tools/cloudsploit", env={**os.environ})
        except subprocess.TimeoutExpired:
            return "Cloudsploit timed out."
        except FileNotFoundError:
            return "node not found."
        try:
            with open(json_out) as f:
                data = json.load(f)
            counts = {}
            for item in data:
                s = item.get("status","unknown")
                counts[s] = counts.get(s,0) + 1
            summary = " | ".join(f"{k}: {v}" for k,v in counts.items())
        except Exception:
            summary = "Could not parse results."
        return f"Cloudsploit complete.\n{summary}\nJSON: {json_out}\nHTML: {html_out}"

    @mcp.tool()
    async def aws_service_enum(service: str, region: str = "us-east-1") -> str:
        """Quick boto3 enumeration for a specific service: s3 / ec2 / lambda / rds / secretsmanager / cloudtrail"""
        client = boto3.client(service, region_name=region)
        results = {"service": service, "region": region}
        try:
            if service == "s3":
                results["buckets"] = [{"name":b["Name"]} for b in boto3.client("s3").list_buckets()["Buckets"]]
            elif service == "ec2":
                instances = boto3.client("ec2",region_name=region).describe_instances()
                results["instances"] = [{"id":i["InstanceId"],"type":i["InstanceType"],"state":i["State"]["Name"],"public_ip":i.get("PublicIpAddress")} for r in instances["Reservations"] for i in r["Instances"]]
            elif service == "lambda":
                results["functions"] = [{"name":f["FunctionName"],"runtime":f.get("Runtime")} for f in boto3.client("lambda",region_name=region).list_functions()["Functions"]]
            elif service == "secretsmanager":
                results["secrets"] = [{"name":s["Name"],"arn":s["ARN"]} for s in boto3.client("secretsmanager",region_name=region).list_secrets()["SecretList"]]
            elif service == "rds":
                results["databases"] = [{"id":db["DBInstanceIdentifier"],"engine":db["Engine"],"public":db.get("PubliclyAccessible")} for db in boto3.client("rds",region_name=region).describe_db_instances()["DBInstances"]]
            elif service == "cloudtrail":
                results["trails"] = [{"name":t["Name"],"multi_region":t.get("IsMultiRegionTrail")} for t in boto3.client("cloudtrail",region_name=region).describe_trails()["trailList"]]
            else:
                return f"Service {service} not implemented. Use prowler_scan or scoutsuite_scan."
        except Exception as e:
            results["error"] = str(e)
        return json.dumps(results, indent=2, default=str)
