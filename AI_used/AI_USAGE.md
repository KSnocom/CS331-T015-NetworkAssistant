# Tools 

ChatGPT, Google search AI, Ollama Qwen3 4b (local model for calling tools).

#  Prompts

> I am building an Intelligent Network Configuration Assistant using MCP and rule-based automation on Fedora Linux make a local network configuration automation system through MCP

> It should support blocking and allowing IP addresses and ports, applying and removing bandwidth limits

> Give code for showing firewall and bandwidth rules, pinging hosts, and validating bandwidth with iperf3

> Use constrained mcp tools, input validation, yaml policies, a safe command builder, one centralized command runner, dry-run and live modes, kernel-state verification, and audit logging

> How to create docker network with admin container and two client containers

> How to check connectivity between docker admin and client A and client B

> docker run --rm hello-world docker compose version permission denied while trying to connect to the docker API at unix:///var/run/docker.sock Docker Compose version v5.5.1 what is the error

> Give command to limit bandwidth from client A to 5mbps and how to unrestrict it

> What is the (.venv)(.venv)$ part in terminal?

> Create the Python command runner dont expose an execute_command() function the model should only call constrained tools, and Python must build the exact command after validation and policy checks

> Put all subprocess execution in one centralized python module capture the command, return code, stdout, stderr, timestamp, and duration i need both dry-run and live modes use fixed argument lists, shell=False, an executable allowlist, and bounded timeouts

> How to add validators for IPv4 and IPv6 addresses, ports from 1 to 65535, tcp/udp/icmp protocols, bandwidth values

> Create pytest tests for valid inputs and invalid inputs

> Add yaml firewall and bandwidth policies

> Explain the difference between input validation and policy validation, and explain what the Python checks test and how I can rerun them


> Implement block_ip, allow_ip, block_port, allow_port, limit_bandwidth, remove_bandwidth_limit, ping_host, validate_bandwidth, show_firewall_rules, and show_bandwidth_rules

> BLOCK_PORT 70fc5066-43b4-4c2e-b380-ff2f58ef1241: found 0 final audit records BLOCK_PORT 289b72dc-e4f1-4c27-bf30-59aba3fbc3de: found 0 final audit records BLOCK_PORT 75f96ea3-bbf9-4a17-8aca-9b5f2dbee6db: found 0 final audit records BLOCK_PORT de9010c7-d6d4-498c-aaaf-04c3c5f4e2e1: found 0 final audit records BLOCK_PORT c415b730-7667-49b7-8f79-43ff1fa2df70: found 0 final audit records what is the error here

> Make firewall operations like so repeated requests dont create duplicate rules and allow operations should remove only the assistant's matching DROP rule.

> Code for per-host bandwidth limits using tc HTB classes and destination filters verify the qdisc, class rate, ceiling, and host filter after applying a limit.

> How to add bounded ping and iperf3 commands and return structured results through the same runner

> Give code for a working mcp server that exposes only the ten fixed network tools add a client that can list the tools and call them with set arguments.

> How to download ollama, qwen3:4b

> Add a command-line chat interface using the local Ollama qwen3:4b model, Qwen should interpret the admin's text and select one MCP tool with json arguments it must never generate a shell command for execution.

> The model returned text instead of calling the tool, make the Qwen response use schema constrained json so a input like as "Block TCP port 23" produces block_port with port 23, protocol tcp, and direction INPUT

> How can I make the Qwen work faster?

> Add  audit logging

> Show me where the executed commands are stored and how to display the latest five audit records

> Check that every application response has exactly one matching final audit record

> Where can i add more on non functional requirements test security, performance, scalability, reliability, repeatability, concurrency, bounded failures, and auditability in the isolated container environment

> Make python test files for  invalid IP rejection, protected-host and protected-port rejection, repeated requests, concurrent requests, final cleanup, and whether normal operation returns after removing firewall and bandwidth rules

> python -m pytest -q tests/test_validators.py tests/test_policy.py Requirement already satisfied: pyyaml in ./.venv/lib64/python3.14/site-packages (6.0.3) ..............................................................           [100%] 62 passed in 0.08s (.venv) (.venv) $ what does this mean 

> Send eight concurrent calls across two mcp servers and confirm that they change only once

> Measure live mcp backend latency over repeated samples and report the median, p95, and maximum. Keep Qwen inference and server startup aside from backend timing

> Test an unreachable connectivity probe with a 12 second test budget and verify that it returns a bounded failure rather than hanging

> The bandwidth commands succeeded, but output "Rate/filter verification failed. Inspect tc JSON and saved pending state before continuing." fix this

> Why the host and container logs do not match

> python -m src.chat: error: unrecognized arguments: exit (.venv) ks@fedora:~/code$ docker compose -f docker/docker-compose.ymp up -d compose file "/home/ks/code/docker/docker-compose.ymp" is invalid: open /home/ks/code/docker/docker-compose.ymp: no such file or directory (.venv) ks@fedora:~/code$  fix

> The container reports "/opt/venv/bin/python3: No module named src.server" and the MCP connection closes. Explain how to copy or include the source code in the admin container and verify the import

> The chat client says "service admin is not running." how to start compose lab

> Ok now give me some new commands and show me where it stores the command executed

> i requested bandwidth limit "Stored state belongs to a different network context. Stop and reconcile state after container recreation." what is the error

> Give the complete first-time setup: install Docker, install Ollama and qwen3:4b, clone the repository, create and activate the Python virtual environment, install requirements.txt, build and start the Compose lab, run the tests, and launch src.chat

> Explain one complete request, like as "Limit bandwidth to Client A to 7 Mbps," including which Python file receives it which function is called, how mcp transports it, how validation and policy work, how tc commands are constructed and executed, how kernel state is verified, and where the audit record is stored

> What improvements can I make on this

> Push on github command

# Thought Process

> AI was used to understand what the final deliverables expected are, and how to get there step by step.

> Any issues we faced were diagnosed using ChatGPT and it was used to give us the fixed code for MCP server, chat.py and testing and validation files.

# Step by step details

>Planning: AI helped us define the architecture, project structure, tools, policies, and security boundaries.

>Implementation: ChatGPT suggested Python modules, MCP tools (and code), validation logic, safe command construction, Docker configuration, and audit logging.

>Testing: We asked chatGPT to give us commands to test concurrency, policy rejection and failure handling tests.

>Debugging: We used AI to help us fix errors in our shell commands and backent python files. 

>Validation: AI helped us interpret pytest, iptables, tc, ping, iperf3, latency, and audit results.
