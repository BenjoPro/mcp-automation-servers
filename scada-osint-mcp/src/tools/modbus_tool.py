import asyncio
import subprocess
from typing import Any
from ..utils.logger import setup_logger

logger = setup_logger(__name__)

async def run(args: dict[str, Any]) -> str:
    host = args.get("host")
    if not host:
        return "[ERROR] 'host' is required."

    port = args.get("port", 502)
    action = args.get("action", "device_info")
    unit_id = args.get("unit_id", 1)
    start_addr = args.get("start_address", 0)
    count = args.get("count", 10)
    timeout = args.get("timeout", 5)

    if action == "scan_unit_ids":
        return await _scan_unit_ids(host, port, timeout)
    elif action == "device_info":
        return await _device_info(host, port, unit_id, timeout)
    elif action == "read_coils":
        return await _read_coils(host, port, unit_id, start_addr, count, timeout)
    elif action == "read_registers":
        return await _read_registers(host, port, unit_id, start_addr, count, timeout)
    elif action == "read_inputs":
        return await _read_inputs(host, port, unit_id, start_addr, count, timeout)
    else:
        return f"[ERROR] Unknown action: {action}"

async def _device_info(host, port, unit_id, timeout):
    try:
        from pymodbus.client import ModbusTcpClient
        from pymodbus.mei_message import ReadDeviceInformationRequest

        client = ModbusTcpClient(host, port=port, timeout=timeout)
        if not client.connect():
            return f"[ERROR] Cannot connect to {host}:{port}"

        lines = [
            "=" * 50,
            f"  MODBUS DEVICE INFO — {host}:{port} (Unit {unit_id})",
            "=" * 50,
        ]
        try:
            req = ReadDeviceInformationRequest(read_code=0x01, object_id=0x00, slave=unit_id)
            resp = client.execute(req)
            if not resp.isError():
                labels = {0: "VendorName", 1: "ProductCode", 2: "Revision",
                          3: "VendorURL", 4: "ProductName", 5: "ModelName"}
                for obj_id, obj_val in resp.information.items():
                    val = obj_val.decode("utf-8", errors="replace") if isinstance(obj_val, bytes) else str(obj_val)
                    lines.append(f"  {labels.get(obj_id, f'Obj{obj_id}'):20s}: {val}")
            else:
                lines.append(f"  FC43 not supported: {resp}")
        except Exception as e:
            lines.append(f"  FC43 error: {e}")

        try:
            rr = client.read_holding_registers(0, count=4, slave=unit_id)
            if not rr.isError():
                lines.append(f"  Holding Regs[0-3]: {rr.registers}")
        except Exception:
            pass

        client.close()
        lines.append("=" * 50)
        return "\n".join(lines)

    except ImportError:
        return await _modbus_cli_fallback(host, port, unit_id)
    except Exception as exc:
        return f"[ERROR] Modbus device_info: {exc}"

async def _read_registers(host, port, unit_id, start, count, timeout):
    try:
        from pymodbus.client import ModbusTcpClient
        client = ModbusTcpClient(host, port=port, timeout=timeout)
        if not client.connect():
            return f"[ERROR] Cannot connect to {host}:{port}"
        rr = client.read_holding_registers(start, count=count, slave=unit_id)
        client.close()
        if rr.isError():
            return f"[ERROR] {rr}"
        lines = [f"  HOLDING REGISTERS — {host}:{port} unit={unit_id} addr={start}"]
        for i, val in enumerate(rr.registers):
            lines.append(f"  Reg[{start+i:05d}]: {val:5d}  (0x{val:04X})")
        return "\n".join(lines)
    except Exception as exc:
        return f"[ERROR] read_registers: {exc}"

async def _read_coils(host, port, unit_id, start, count, timeout):
    try:
        from pymodbus.client import ModbusTcpClient
        client = ModbusTcpClient(host, port=port, timeout=timeout)
        if not client.connect():
            return f"[ERROR] Cannot connect to {host}:{port}"
        rr = client.read_coils(start, count=count, slave=unit_id)
        client.close()
        if rr.isError():
            return f"[ERROR] {rr}"
        lines = [f"  COILS — {host}:{port} unit={unit_id} addr={start}"]
        for i, val in enumerate(rr.bits[:count]):
            lines.append(f"  Coil[{start+i:05d}]: {'ON ' if val else 'OFF'}")
        return "\n".join(lines)
    except Exception as exc:
        return f"[ERROR] read_coils: {exc}"

async def _read_inputs(host, port, unit_id, start, count, timeout):
    try:
        from pymodbus.client import ModbusTcpClient
        client = ModbusTcpClient(host, port=port, timeout=timeout)
        if not client.connect():
            return f"[ERROR] Cannot connect to {host}:{port}"
        rr = client.read_input_registers(start, count=count, slave=unit_id)
        client.close()
        if rr.isError():
            return f"[ERROR] {rr}"
        lines = [f"  INPUT REGISTERS — {host}:{port} unit={unit_id} addr={start}"]
        for i, val in enumerate(rr.registers):
            lines.append(f"  InReg[{start+i:05d}]: {val:5d}  (0x{val:04X})")
        return "\n".join(lines)
    except Exception as exc:
        return f"[ERROR] read_inputs: {exc}"

async def _scan_unit_ids(host, port, timeout):
    lines = [f"  UNIT ID SCAN — {host}:{port}", "  Scanning IDs 1-247..."]
    responding = []
    try:
        from pymodbus.client import ModbusTcpClient
        client = ModbusTcpClient(host, port=port, timeout=timeout)
        if not client.connect():
            return f"[ERROR] Cannot connect to {host}:{port}"
        for uid in range(1, 248):
            try:
                rr = client.read_holding_registers(0, count=1, slave=uid)
                if not rr.isError():
                    responding.append(uid)
            except Exception:
                pass
        client.close()
        lines.append(f"  Responding unit IDs: {responding if responding else 'None'}")
    except Exception as exc:
        lines.append(f"  Error: {exc}")
    return "\n".join(lines)

async def _modbus_cli_fallback(host, port, unit_id):
    cmd = ["modbus", "read", f"{host}:{port}", "%MW0:r4"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            return f"  modbus-cli output:\n{result.stdout}"
        return f"[ERROR] modbus-cli: {result.stderr}"
    except FileNotFoundError:
        return "[ERROR] Neither pymodbus nor modbus-cli available."
    except Exception as exc:
        return f"[ERROR] modbus-cli fallback: {exc}"

