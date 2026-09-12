# Tools 

ChatGPT, Google search AI, Ollama Qwen3 4b (local model for calling tools).

#  Prompts

> I am building an Intelligent Network Configuration Assistant using MCP and rule-based automation on Fedora Linux. Build a local network-configuration automation system exposed through MCP. 

>It should support blocking and allowing IP addresses and ports, applying and removing bandwidth limits,

>Give code for showing firewall and bandwidth rules, pinging hosts, and validating bandwidth with iperf3. 

>Use structured MCP tools, input validation, YAML policies, a safe command builder, one centralized command runner, dry-run and live modes, kernel-state verification, and JSONL audit logging.

> How to create docker network with admin container and two client containers.

> How to check connectivity between docker admin and client A and client B

> Give command to limit bandwidth from client A to 5mbps and how to unrestrict it

> Create the Python command layer. Do not expose an execute_command(command: str) function. The model should only call constrained tools, and Python must build the exact command after validation and policy checks.

> Put all subprocess execution in one centralized Python module. Capture the command, return code, stdout, stderr, timestamp, and duration. Support both dry-run and live modes. Use fixed argument lists, shell=False, an executable allowlist, and bounded timeouts.

> How to add validators for IPv4 and IPv6 addresses, CIDR ranges, ports from 1 to 65535, tcp/udp/icmp protocols, bandwidth values.

> Create pytest tests for valid inputs and invalid inputs.

> Add YAML firewall and bandwidth policies.
> Explain the difference between input validation and policy validation, and explain what the Python checks test and how I can rerun them.


> Implement block_ip, allow_ip, block_port, allow_port, limit_bandwidth, remove_bandwidth_limit, ping_host, validate_bandwidth, show_firewall_rules, and show_bandwidth_rules.

> Make firewall operations idempotent so repeated requests do not create duplicate managed rules. Allow operations should remove only the assistant's matching DROP rule.

> Code for per-host bandwidth limits using tc HTB classes and destination filters. Verify the qdisc, class rate, ceiling, and host filter after applying a limit.

> How to add bounded ping and iperf3 commands and return structured results through the same centralized runner.

> Generate code for a working MCP server that exposes only the ten approved network tools. Add a client that can list the tools and call them with structured arguments.

> Add a command-line chat interface using the local Ollama qwen3:4b model. Qwen should interpret the administrator's text and select one MCP tool with JSON arguments. It must never generate a shell command for execution.

> The model returned prose instead of calling the tool. Make the Qwen response use schema-constrained JSON so a request such as "Block TCP port 23" produces block_port with port 23, protocol tcp, and direction INPUT.

> How can I make the Qwen work faster?

> Add JSONL audit logging. Record a request ID, timestamp, action, parameters, mode, policy result, execution result, validation result, exact command arguments, and final message.

> Show me where the executed commands are stored and how to display the latest five audit records.

> Check that every application response has exactly one matching final audit record.

> Focus more on non-functional requirements. Test security, performance, scalability, reliability, repeatability, concurrency, bounded failures, and auditability in the isolated container environment.

> Test invalid IP rejection, protected-host and protected-port rejection, repeated requests, concurrent requests, final cleanup, and whether normal operation returns after removing firewall and bandwidth rules.

> Send eight concurrent calls across two MCP servers and confirm that they create one change and seven no-ops rather than duplicate firewall rules like acid rules.

> Measure live MCP backend latency over repeated samples and report the median, P95, and maximum. Keep Qwen inference and server startup separate from backend timing.

> Test an unreachable connectivity probe with a 12 second test budget and verify that it returns a bounded failure rather than hanging.

> The bandwidth commands succeeded, but the service returned: "Rate/filter verification failed. Inspect tc JSON and saved pending state before continuing." Diagnose the tc JSON output and correct verification.

> The non-functional suite passed every check except audit coverage. It reported 79 application responses but zero matching final audit records. Diagnose why the host and container logs do not match.

> Docker inspect shows that the admin container has no mounts. Update the Compose setup so the application audit log persists on the host.

> The container reports "/opt/venv/bin/python3: No module named src.server" and the MCP connection closes. Explain how to copy or include the source code in the admin container and verify the import.

> The chat client reports "service admin is not running." Explain how to start the Compose lab, check container status, and inspect admin logs if it exits.

> A bandwidth request reports "Stored state belongs to a different network context. Stop and reconcile state after container recreation." Explain how to inspect current tc qdisc, class, and filter state before archiving stale bandwidth state.

> Give the complete first-time setup: install Docker, install Ollama and qwen3:4b, clone the repository, create and activate the Python virtual environment, install requirements.txt, build and start the Compose lab, run the tests, and launch src.chat.

> Explain one complete request, such as "Limit bandwidth to Client A to 7 Mbps," including which Python file receives it, which function is called, how MCP transports it, how validation and policy work, how tc commands are constructed and executed, how kernel state is verified, and where the audit record is stored.

# Thought Process

> AI was used to understand what the final deliverables expected are, and how to get there step by step.

> Any issues we faced were diagnosed using ChatGPT and it was used to give us the fixed code for MCP server, chat.py and testing and validation files.

# Step by step details

>Planning: AI helped us define the architecture, project structure, tools, policies, and security boundaries.

>Implementation: ChatGPT suggested Python modules, MCP tools (and code), validation logic, safe command construction, Docker configuration, and audit logging.

>Testing: We asked chatGPT to give us commands to test concurrency, policy rejection and failure handling tests.

>Debugging: We used AI to help us fix errors in our shell commands and backent python files. 

>Validation: AI helped us interpret pytest, iptables, tc, ping, iperf3, latency, and audit results.
