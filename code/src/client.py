"""Command-line MCP client. Tool arguments are JSON, never shell commands."""

import argparse
import asyncio
import json
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def run(args):
    compose_file = (
        Path(__file__).resolve().parents[1]
        / "docker" / "docker-compose.yml"
    )

    parameters = StdioServerParameters(
        command="docker",
        args=[
            "compose", "-f", str(compose_file),
            "exec", "-T", "admin",
            "python3", "-m", "src.server",
            "--mode", args.mode,
        ],
    )

    async with stdio_client(parameters) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            if args.list_tools:
                listing = await session.list_tools()
                for tool in listing.tools:
                    print(f"{tool.name}: {tool.description}")
                return 0

            arguments = json.loads(args.args)
            if not isinstance(arguments, dict):
                raise ValueError("--args must contain a JSON object")

            response = await session.call_tool(args.tool, arguments)

            payload = response.structuredContent
            if payload is None:
                texts = [
                    block.text for block in response.content
                    if block.type == "text"
                ]
                try:
                    payload = json.loads("\n".join(texts))
                except ValueError:
                    payload = {"messages": texts}

            print(json.dumps(payload, indent=2))

            if response.isError:
                return 1
            if isinstance(payload, dict) and payload.get("status") in {
                "error", "audit_error", "verification_failed", "invalid", "rejected"
            }:
                return 1
            return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("tool", nargs="?")
    parser.add_argument("--args", default="{}")
    parser.add_argument("--mode", choices=("dry-run", "live"), default="dry-run")
    parser.add_argument("--list-tools", action="store_true")
    args = parser.parse_args()

    if not args.list_tools and not args.tool:
        parser.error("Supply a tool name or --list-tools")

    raise SystemExit(asyncio.run(run(args)))


if __name__ == "__main__":
    main()
