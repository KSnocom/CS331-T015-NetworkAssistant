# AI Usage 

## Tools

**ChatGPT** supported troubleshooting, test code, and documentation. **Qwen3:4b through Ollama** was the project's local model for interpreting administrator requests.

## Prompts

Representative testing and validation prompts used:

- Code to Verify firewall blocking and restoration, and compare iperf3 throughput before and after a bandwidth limit.
- Code required to set up docker and containerised clients, admin.
- YAML syntax to ensure that the commands fit the policy.
- Diagnose failures using pasted command output, test results, and audit records.

## Thought Process / Workflow

AI was used iteratively to fix project errors and meet and to implement test steps. Reported measurements came from the local runs; untested behavior was identified as a limitation. 

## Step-by-Step Contribution

1. **Implementation:** Drafted Python testing scripts and container setup commands.
2. **Testing:** Helped develop pytest cases and live checks for validation, repeat requests, concurrency, latency, and audit coverage.
3. **Debugging:** Suggested corrections for command verification, container configuration, and audit-log persistence based on observeed errors.
