"""One-request, one-tool Ollama-to-MCP terminal client."""

import argparse
import asyncio
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
from src.ollama_planner import choose_tool
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


ROOT = Path(__file__).resolve().parents[1]

EXPECTED_TOOLS = {
    "block_ip", "allow_ip", "block_port", "allow_port",
    "limit_bandwidth", "remove_bandwidth_limit",
    "ping_host", "validate_bandwidth",
    "show_firewall_rules", "show_bandwidth_rules",
}

SYSTEM = """
You translate administrator requests into exactly one provided network tool.
Client A is 172.30.50.20. Client B is 172.30.50.30.
Admin is 172.30.50.10. Bandwidth is expressed in Mbps.
For firewall requests, use INPUT unless another direction is explicit.
For a clear request, call the appropriate tool; the backend decides policy.
Do not invent addresses, ports, protocols, rates, or tool results.
If essential information is missing, ask a short clarification question.
If multiple actions are requested, ask for one action at a time.
Never generate or execute shell commands.
Never claim that an operation succeeded without a tool result.
Each user message is independent, so require an explicit target.
"""


def log(event):
    path = ROOT / "logs/chat-client.jsonl"
    path.parent.mkdir(exist_ok=True)
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **event,
    }
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record) + "\n")


async def chat(args):
    parameters = StdioServerParameters(
        command="docker",
        args=[
            "compose", "-f", str(ROOT / "docker/docker-compose.yml"),
            "exec", "-T", "admin",
            "python3", "-m", "src.server", "--mode", args.mode,
        ],
    )

    async with stdio_client(parameters) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            listing = await session.list_tools()

            names = {tool.name for tool in listing.tools}
            if names != EXPECTED_TOOLS:
                raise RuntimeError("Unexpected MCP tool registry")

            tools = [
                {
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description or "",
                        "parameters": tool.inputSchema,
                    },
                }
                for tool in listing.tools
            ]

            async with httpx.AsyncClient(
                base_url="http://127.0.0.1:11434",
                timeout=httpx.Timeout(180.0, connect=5.0),
                trust_env=False,
            ) as http:
                print(f"\nNetwork Assistant | model={args.model} | mode={args.mode}")
                print("One request per message. Type exit to stop.\n")

                while True:
                    try:
                        prompt = await asyncio.to_thread(input, "You> ")
                    except EOFError:
                        break

                    if prompt.strip().lower() in {"exit", "quit"}:
                        break
                    if not prompt.strip():
                        continue
                    if len(prompt) > 4000:
                        print("Please shorten the request to 4000 characters.")
                        continue

                    phase = "model"
                    try:
                        started = time.perf_counter()
                        message = await choose_tool(
                            http, args.model, prompt, tools,
                            args.mode, SYSTEM,
                        )
                        model_ms = (time.perf_counter() - started) * 1000
                        calls = message.get("tool_calls") or []

                        if not calls:
                            print("No tool executed.")
                            print(message.get("content") or "Please rephrase.")
                            log({
                                "prompt": prompt,
                                "mode": args.mode,
                                "phase": "no_tool",
                                "model_message": message,
                                "model_ms": model_ms,
                            })
                            continue

                        if len(calls) != 1:
                            raise ValueError("Please request exactly one action.")

                        function = calls[0]["function"]
                        name = function["name"]
                        arguments = function["arguments"]

                        if name not in names or not isinstance(arguments, dict):
                            raise ValueError("Model returned an invalid tool call")

                        print(f"Tool: {name} {json.dumps(arguments)}")
                        log({
                            "prompt": prompt,
                            "mode": args.mode,
                            "phase": "selected",
                            "tool": name,
                            "arguments": arguments,
                        })

                        phase = "mcp"
                        started = time.perf_counter()
                        reply = await session.call_tool(name, arguments)
                        mcp_ms = (time.perf_counter() - started) * 1000

                        result = reply.structuredContent
                        if result is None:
                            text = "\n".join(
                                block.text for block in reply.content
                                if block.type == "text"
                            )
                            try:
                                result = json.loads(text)
                            except ValueError:
                                result = {"message": text}

                        if not isinstance(result, dict):
                            result = {"data": result}
                        if reply.isError:
                            result["status"] = "mcp_error"

                        log({
                            "prompt": prompt,
                            "mode": args.mode,
                            "phase": "result",
                            "tool": name,
                            "arguments": arguments,
                            "model_ms": model_ms,
                            "mcp_ms": mcp_ms,
                            "result": result,
                        })

                        print(
                            "Result:", result.get("status"),
                            "| execution:", result.get("execution_result"),
                            "| validation:", result.get("validation_result"),
                        )
                        if result.get("message"):
                            print(result["message"])
                        if "data" in result:
                            print(json.dumps(result["data"], indent=2))
                        print(f"Model: {model_ms:.0f} ms | MCP: {mcp_ms:.1f} ms\n")

                    except Exception as exc:
                        log({
                            "prompt": prompt,
                            "mode": args.mode,
                            "phase": "error",
                            "stage": phase,
                            "error": str(exc),
                        })
                        print(f"Request failed during {phase}: {exc}")
                        if phase == "mcp":
                            print("Inspect current rules before retrying a change.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="qwen3:4b")
    parser.add_argument("--mode", choices=("dry-run", "live"), default="dry-run")
    args = parser.parse_args()
    try:
        asyncio.run(chat(args))
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
