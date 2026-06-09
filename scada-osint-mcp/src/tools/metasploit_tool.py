import asyncio
import os
import tempfile
from typing import Any
from ..utils.logger import setup_logger

logger = setup_logger(__name__)

MSF_MODULES = {
    "modbus_findunitid": {
        "module": "auxiliary/scanner/scada/modbus_findunitid",
        "options": {"RHOSTS": "{target}", "RPORT": "502"},
    },
    "modbus_client": {
        "module": "auxiliary/scanner/scada/modbus_client",
        "options": {"RHOSTS": "{target}", "RPORT": "502"},
    },
    "bacnet_device_info": {
        "module": "auxiliary/scanner/scada/bacnet_device_info",
        "options": {"RHOSTS": "{target}", "RPORT": "47808"},
    },
    "profinet_dcp_discover": {
        "module": "auxiliary/scanner/scada/profinet_dcp_discover",
        "options": {"INTERFACE": "eth0"},
    },
    "siemens_s7_info": {
        "module": "auxiliary/scanner/scada/siemens_s7_300_400_default_password",
        "options": {"RHOSTS": "{target}", "RPORT": "102"},
    },
    "dnp3_serial_info": {
        "module": "auxiliary/scanner/scada/dnp3_serial_info",
        "options": {"RHOSTS": "{target}", "RPORT": "20000"},
    },
    "ethernet_ip_list_identity": {
        "module": "auxiliary/scanner/scada/advantech_webaccess_dbvisitor",
        "options": {"RHOSTS": "{target}", "RPORT": "44818"},
    },
}

PRESET_ALL = [
    "modbus_findunitid",
    "bacnet_device_info",
    "siemens_s7_info",
    "dnp3_serial_info",
]

async def run(args: dict[str, Any]) -> str:
    target = args.get("target")
    if not target:
        return "[ERROR] 'target' is required."

    module_key = args.get("module", "ics_preset_all")
    timeout = args.get("timeout", 30)
    port_override = args.get("port")

    proc = await asyncio.create_subprocess_exec(
        "which", "msfconsole",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    await proc.communicate()
    if proc.returncode != 0:
        return _msf_not_available(target, module_key)

    modules_to_run = PRESET_ALL if module_key == "ics_preset_all" else [module_key]

    results = []
    for mk in modules_to_run:
        result = await _run_module(mk, target, port_override, timeout)
        results.append(f"  -- {mk} --\n{result}")

    lines = [
        "=" * 50,
        f"  METASPLOIT ICS SCAN — {target}",
        "=" * 50,
    ] + results + ["=" * 50]

    return "\n".join(lines)

async def _run_module(module_key, target, port_override, timeout):
    cfg = MSF_MODULES.get(module_key)
    if not cfg:
        return f"  [ERROR] Unknown module: {module_key}"

    options = {k: v.replace("{target}", target) for k, v in cfg["options"].items()}
    if port_override:
        options["RPORT"] = str(port_override)

    rc_lines = [f"use {cfg['module']}"]
    for k, v in options.items():
        rc_lines.append(f"set {k} {v}")
    rc_lines += ["set VERBOSE true", "run", "exit"]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rc", delete=False) as f:
        f.write("\n".join(rc_lines))
        rc_path = f.name

    try:
        proc = await asyncio.create_subprocess_exec(
            "msfconsole", "-q", "-r", rc_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        output = stdout.decode("utf-8", errors="replace")
        filtered = "\n".join(
            line for line in output.splitlines()
            if any(m in line for m in ["[*]", "[+]", "[-]"])
        )
        return filtered[:3000] if filtered else output[:1000]
    except asyncio.TimeoutError:
        return f"  [TIMEOUT] {module_key} exceeded {timeout}s"
    except Exception as exc:
        return f"  [ERROR] {exc}"
    finally:
        os.unlink(rc_path)

def _msf_not_available(target, module):
    return (
        "  msfconsole not found in container.\n"
        "  To enable Metasploit, add to Dockerfile:\n\n"
        "    FROM metasploitframework/metasploit-framework AS msf\n"
        "    COPY --from=msf /usr/src/metasploit-framework /opt/msf\n\n"
        f"  Manual equivalent:\n"
        f"    msfconsole -q -x 'use auxiliary/scanner/scada/modbus_findunitid; set RHOSTS {target}; run'\n"
        f"    msfconsole -q -x 'use auxiliary/scanner/scada/bacnet_device_info; set RHOSTS {target}; run'"
    )

