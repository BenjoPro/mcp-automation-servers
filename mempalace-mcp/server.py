import sys
import json
import logging
from database import init_db
from tools import TOOLS, HANDLERS

logging.basicConfig(level=logging.DEBUG, stream=sys.stderr)
logger = logging.getLogger("mempalace")


def send(obj: dict):
    line = json.dumps(obj, ensure_ascii=False)
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def handle_message(msg: dict):
    method = msg.get("method")
    msg_id = msg.get("id")

    if method == "initialize":
        send({
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "MemPalace-MCP", "version": "1.0.0"}
            }
        })

    elif method == "notifications/initialized":
        pass

    elif method == "tools/list":
        send({
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {"tools": TOOLS}
        })

    elif method == "tools/call":
        tool_name = msg.get("params", {}).get("name")
        tool_args = msg.get("params", {}).get("arguments", {})
        handler = HANDLERS.get(tool_name)
        if not handler:
            send({
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"}
            })
            return
        try:
            result = handler(tool_args)
            send({
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [{"type": "text", "text": result}]
                }
            })
        except Exception as e:
            logger.error(f"Tool error: {e}")
            send({
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32603, "message": str(e)}
            })

    else:
        if msg_id is not None:
            send({
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"}
            })


def main():
    init_db()
    logger.info("MemPalace-MCP started")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
            handle_message(msg)
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {e}")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")


if __name__ == "__main__":
    main()
