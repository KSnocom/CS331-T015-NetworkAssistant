"""Translate a request into a validated tool selection."""

import json

from pydantic import BaseModel, ConfigDict, Field, StrictStr


class Decision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool: StrictStr
    arguments: dict
    message: StrictStr = Field(max_length=200)


async def choose_tool(http, model, prompt, tools, mode, system_prompt):
    allowed = {item["function"]["name"] for item in tools}
    schema = Decision.model_json_schema()
    schema["properties"]["tool"]["enum"] = sorted(allowed | {"clarify"})

    instructions = system_prompt + """
Return only a JSON object with tool, arguments, and message.
Choose a tool from the supplied definitions.
Use the exact argument names and JSON types from its parameters.
For a tool selection, message must be an empty string.
For missing information, select clarify, use empty arguments,
and put one short question in message.

Example:
Request: Block TCP port 23
Response:
{"tool":"block_port","arguments":{"port":23,"protocol":"tcp","direction":"INPUT"},"message":""}
"""

    response = await http.post("/api/chat", json={
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    instructions
                    + "\nMode: " + mode
                    + "\nTool definitions:\n" + json.dumps(tools)
                    + "\nResponse schema:\n" + json.dumps(schema)
                ),
            },
            {"role": "user", "content": prompt},
        ],
        "format": schema,
        "stream": False,
        "think": False,
        "options": {
            "temperature": 0,
            "num_ctx": 8192,
            "num_predict": 1024,
        },
    })
    response.raise_for_status()
    payload = response.json()

    if payload.get("done_reason") == "length":
        raise ValueError("Model output was truncated; no tool will execute")

    decision = Decision.model_validate_json(payload["message"]["content"])

    if decision.tool == "clarify":
        if decision.arguments or not decision.message.strip():
            raise ValueError("Invalid clarification response")
        return {"content": decision.message, "tool_calls": []}

    if decision.tool not in allowed:
        raise ValueError("Model selected an unknown tool")

    # This is the bridge's normalized selection, not shell text.
    # MCP performs the tool-specific argument validation.
    return {
        "content": "",
        "tool_calls": [{
            "function": {
                "name": decision.tool,
                "arguments": decision.arguments,
            },
        }],
    }
