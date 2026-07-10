#!/usr/bin/env python3
"""A minimal MCP-ish stdio server for testing the Warden proxy.

Reads newline-delimited JSON-RPC requests on stdin and writes responses on
stdout. Just enough to exercise the proxy's forward path.
"""
import json
import sys


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        req = json.loads(line)
        method = req.get("method")
        if method == "tools/call":
            params = req.get("params", {})
            name = params.get("name")
            args = params.get("arguments", {})
            result = {
                "content": [{"type": "text", "text": f"executed {name}({json.dumps(args)})"}],
                "isError": False,
            }
        elif method == "tools/list":
            result = {"tools": [{"name": "wire_funds"}, {"name": "delete_database"}]}
        else:
            result = {}
        resp = {"jsonrpc": "2.0", "id": req.get("id"), "result": result}
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
