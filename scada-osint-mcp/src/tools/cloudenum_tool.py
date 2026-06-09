import asyncio
import os
from typing import Any
from ..utils.logger import setup_logger

logger = setup_logger(__name__)

CLOUD_ENUM_PATH = "/opt/cloud_enum/cloud_enum.py"

ICS_CLOUD_KEYWORDS = {
    "siemens":   ["siemens-scada", "siemens-ot", "siemens-plc"],
    "schneider": ["schneider-scada", "schneidere", "se-scada"],
    "rockwell":  ["rockwellautomation", "allen-bradley"],
    "honeywell": ["honeywell-ot", "honeywell-scada"],
    "ge":        ["ge-digital-scada", "gedigital", "ge-historian"],
    "osisoft":   ["osisoft-pi", "osi-pi", "pi-historian"],
}

async def run(args: dict[str, Any]) -> str:
    keyword = args.get("keyword")
    if not keyword:
        return "[ERROR] 'keyword' is required."

    extra_keywords = args.get("extra_keywords", [])
    providers = args.get("providers", ["aws", "azure", "gcp"])
    timeout = args.get("timeout", 120)

    all_keywords = [keyword] + extra_keywords
    normalized = keyword.lower().replace(" ", "-")
    if normalized in ICS_CLOUD_KEYWORDS:
        all_keywords += ICS_CLOUD_KEYWORDS[normalized]

    if not os.path.exists(CLOUD_ENUM_PATH):
        return _not_installed(keyword, all_keywords, providers)

    cmd = ["python3", CLOUD_ENUM_PATH]
    for kw in all_keywords:
        cmd += ["-k", kw]
    if "aws" not in providers:
        cmd.append("--disable-aws")
    if "azure" not in providers:
        cmd.append("--disable-azure")
    if "gcp" not in providers:
        cmd.append("--disable-gcp")

    logger.info(f"Running cloud_enum: {' '.join(cmd)}")

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd="/opt/cloud_enum",
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        output = stdout.decode("utf-8", errors="replace")
        return _format_output(output, keyword, all_keywords, providers)

    except asyncio.TimeoutError:
        return f"[TIMEOUT] cloud_enum exceeded {timeout}s for '{keyword}'"
    except Exception as exc:
        return f"[ERROR] cloud_enum: {exc}"

def _format_output(output, keyword, keywords, providers):
    lines = [
        "=" * 50,
        f"  CLOUD ENUM — ICS/OT Asset Discovery",
        f"  Keywords : {', '.join(keywords)}",
        f"  Providers: {', '.join(providers)}",
        "=" * 50,
        "",
    ]
    hits = [
        line for line in output.splitlines()
        if any(m in line for m in ["[+]", "OPEN", "exists", "EXPOSED", "PUBLIC"])
    ]
    if hits:
        lines.append("  Discovered Assets:")
        for h in hits:
            lines.append(f"  {h.strip()}")
    else:
        lines.append("  No public cloud assets found.")

    lines += ["", "  -- Full Output --", output[:3000]]
    lines.append("=" * 50)
    return "\n".join(lines)

def _not_installed(keyword, keywords, providers):
    return (
        "  cloud_enum not found at /opt/cloud_enum\n"
        "  Install: git clone https://github.com/initstring/cloud_enum /opt/cloud_enum\n\n"
        f"  Would have searched: {', '.join(keywords)}\n"
        f"  Providers: {', '.join(providers)}\n\n"
        f"  Manual: python3 cloud_enum.py {' '.join(['-k ' + k for k in keywords])}"
    )

