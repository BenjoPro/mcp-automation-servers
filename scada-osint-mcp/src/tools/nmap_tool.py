import asyncio
import xml.etree.ElementTree as ET
from typing import Any
from ..utils.logger import setup_logger

logger = setup_logger(__name__)

SCAN_CONFIGS = {
    "ics_discovery": {
        "ports": "102,502,20000,44818,47808,2404,4840,34962,1911,9600,5007,1200",
        "scripts": "banner,modbus-discover,s7-info",
        "extra": "-sV --version-intensity 5",
    },
    "modbus": {
        "ports": "502",
        "scripts": "modbus-discover",
        "extra": "-sV",
    },
    "s7": {
        "ports": "102",
        "scripts": "s7-info",
        "extra": "-sV",
    },
    "bacnet": {
        "ports": "47808",
        "scripts": "bacnet-info",
        "extra": "-sV -sU",
    },
    "dnp3": {
        "ports": "20000",
        "scripts": "banner",
        "extra": "-sV",
    },
    "full_ics": {
        "ports": "1-65535",
        "scripts": "banner,modbus-discover,s7-info,bacnet-info",
        "extra": "-sV -sU --version-intensity 5 -O",
    },
    "vuln": {
        "ports": "102,502,20000,44818,47808,2404,4840",
        "scripts": "vuln",
        "extra": "-sV",
    },
    "custom": {
        "ports": "",
        "scripts": "banner",
        "extra": "-sV",
    },
}

async def run(args: dict[str, Any]) -> str:
    target = args.get("target")
    if not target:
        return "[ERROR] 'target' is required."

    scan_type = args.get("scan_type", "ics_discovery")
    config = SCAN_CONFIGS.get(scan_type, SCAN_CONFIGS["ics_discovery"])

    ports = args.get("ports") or config["ports"]
    scripts = config.get("scripts", "banner")
    extra = config.get("extra", "-sV")
    timing = args.get("timing", "T3")
    extra_args = args.get("extra_args", "")

    cmd = ["nmap", f"-{timing}"]
    if ports:
        cmd += ["-p", ports]
    if scripts:
        cmd += [f"--script={scripts}"]
    cmd += extra.split()
    if extra_args:
        cmd += extra_args.split()
    cmd += ["-oX", "-", target]

    logger.info(f"Running: {' '.join(cmd)}")

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        xml_output = stdout.decode("utf-8", errors="replace")

        if proc.returncode not in (0, 1):
            return f"[ERROR] nmap exited {proc.returncode}:\n{stderr.decode()[:500]}"

        return _parse_and_format(xml_output, target, scan_type, cmd)

    except asyncio.TimeoutError:
        return "[ERROR] nmap scan timed out (300s)."
    except FileNotFoundError:
        return "[ERROR] nmap not found in container."
    except Exception as exc:
        return f"[ERROR] nmap: {exc}"

def _parse_and_format(xml_data, target, scan_type, cmd):
    lines = [
        "=" * 50,
        f"  NMAP ICS/SCADA SCAN — {scan_type.upper()}",
        f"  Target : {target}",
        f"  Command: {' '.join(cmd)}",
        "=" * 50,
    ]
    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError as e:
        lines.append(f"[WARN] XML parse error: {e}")
        lines.append(xml_data[:2000])
        return "\n".join(lines)

    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        if status_el is not None and status_el.get("state") != "up":
            continue

        addr_el = host_el.find("address[@addrtype='ipv4']")
        ip = addr_el.get("addr", "?") if addr_el is not None else "?"
        hostnames = [hn.get("name","") for hn in host_el.findall("hostnames/hostname")]

        lines.append(f"\n  Host: {ip}")
        if hostnames:
            lines.append(f"  Hostnames: {', '.join(hostnames)}")

        os_el = host_el.find("os/osmatch")
        if os_el is not None:
            lines.append(f"  OS: {os_el.get('name','N/A')} ({os_el.get('accuracy','?')}%)")

        for port_el in host_el.findall("ports/port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") not in ("open", "open|filtered"):
                continue

            portid = port_el.get("portid", "?")
            protocol = port_el.get("protocol", "tcp")
            service_el = port_el.find("service")
            svc_name = service_el.get("name", "?") if service_el is not None else "?"
            product = service_el.get("product", "") if service_el is not None else ""
            version = service_el.get("version", "") if service_el is not None else ""

            lines.append(f"\n  -- {portid}/{protocol} {svc_name} {product} {version} --")

            for script_el in port_el.findall("script"):
                script_id = script_el.get("id", "")
                script_out = script_el.get("output", "").strip()
                if script_out:
                    lines.append(f"  [{script_id}]")
                    for sl in script_out.split("\n")[:10]:
                        lines.append(f"    {sl}")

    lines.append("\n" + "=" * 50)
    return "\n".join(lines)

