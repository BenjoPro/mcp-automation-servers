import os, subprocess, json, sys
import boto3
from botocore.exceptions import ClientError
from mcp.server.fastmcp import FastMCP
from typing import Optional

def register(mcp: FastMCP):

    @mcp.tool()
    async def aws_cli(command: str, region: Optional[str] = None) -> str:
        """Run any AWS CLI command directly. Example: aws s3 ls / aws iam list-users"""
        full_cmd = command if command.startswith("aws ") else f"aws {command}"
        if region:
            full_cmd += f" --region {region}"
        full_cmd += " --output json"
        result = subprocess.run(full_cmd.split(), capture_output=True, text=True, timeout=60)
        return result.stdout or result.stderr

    @mcp.tool()
    async def enumerate_iam_permissions(access_key_id: Optional[str] = None, secret_access_key: Optional[str] = None, session_token: Optional[str] = None, region: str = "us-east-1") -> str:
        """Brute-force enumerate all IAM permissions for the given credentials using enumerate-iam."""
        env = os.environ.copy()
        env["AWS_DEFAULT_REGION"] = region
        if access_key_id:
            env["AWS_ACCESS_KEY_ID"] = access_key_id
        if secret_access_key:
            env["AWS_SECRET_ACCESS_KEY"] = secret_access_key
        if session_token:
            env["AWS_SESSION_TOKEN"] = session_token
        script = "/opt/tools/enumerate-iam/enumerate-iam.py"
        cmd = [sys.executable, script,
               "--access-key", env.get("AWS_ACCESS_KEY_ID",""),
               "--secret-key", env.get("AWS_SECRET_ACCESS_KEY",""),
               "--region", region]
        if env.get("AWS_SESSION_TOKEN"):
            cmd += ["--session-token", env["AWS_SESSION_TOKEN"]]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=900, env=env)
        except subprocess.TimeoutExpired:
            return "enumerate-iam timed out."
        except FileNotFoundError:
            return f"enumerate-iam not found at {script}"
        allowed = [l.strip() for l in result.stdout.splitlines() if "Valid" in l or "granted" in l.lower()]
        with open("/reports/enumerate_iam.json","w") as f:
            f.write(result.stdout)
        return f"Found {len(allowed)} allowed permission(s).\nSaved to /reports/enumerate_iam.json\n\n" + "\n".join(allowed[:50])

    @mcp.tool()
    async def pacu_run_module(module_name: str, session_name: str = "aws-mcp-session", extra_args: Optional[str] = None) -> str:
        """Run a Pacu module. Examples: iam__enum_permissions / iam__privesc_scan / ec2__enum / s3__enum"""
        pacu_dir = "/opt/tools/pacu"
        commands = (f"set_keys\n{os.environ.get('AWS_ACCESS_KEY_ID','')}\n"
                    f"{os.environ.get('AWS_SECRET_ACCESS_KEY','')}\n"
                    f"{os.environ.get('AWS_SESSION_TOKEN','')}\n"
                    f"run {module_name}{' ' + extra_args if extra_args else ''}\nexit\n")
        try:
            result = subprocess.run([sys.executable,"pacu.py","--session",session_name],
                input=commands, capture_output=True, text=True, timeout=600, cwd=pacu_dir)
        except subprocess.TimeoutExpired:
            return f"Pacu module {module_name} timed out."
        except FileNotFoundError:
            return "Pacu not found."
        output = result.stdout + result.stderr
        output_file = f"/reports/pacu_{module_name.replace('__','_')}.txt"
        with open(output_file,"w") as f:
            f.write(output)
        return f"Pacu {module_name} complete. Saved to {output_file}\n\n{output[-3000:]}"

    @mcp.tool()
    async def list_iam_users_roles(region: str = "us-east-1") -> str:
        """Quick IAM inventory: users, roles, groups, policies via boto3."""
        iam = boto3.client("iam", region_name=region)
        results = {}
        for key, fn in [("users", lambda: [{"name":u["UserName"],"arn":u["Arn"]} for u in iam.list_users()["Users"]]),
                        ("roles", lambda: [{"name":r["RoleName"],"arn":r["Arn"]} for r in iam.list_roles()["Roles"]]),
                        ("groups", lambda: [{"name":g["GroupName"],"arn":g["Arn"]} for g in iam.list_groups()["Groups"]])]:
            try:
                results[key] = fn()
            except ClientError as e:
                results[key] = f"Error: {e.response['Error']['Code']}"
        return json.dumps(results, indent=2)
