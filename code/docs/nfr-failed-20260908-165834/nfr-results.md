# Non-functional test results

Overall: **FAIL**

Live MCP requests, including policy, kernel commands, and audit. Excludes server startup and LLM/Ollama processing.

| Check | Result | Detail |
|---|---|---|
| Only the ten approved tools are exposed | PASS |  |
| Initial inspection succeeds | PASS |  |
| No existing assistant firewall rules | PASS | The suite requires an empty managed-firewall baseline. |
| Protected port rejected | PASS | Rejected requests must execute no commands. |
| Command-like IP rejected | PASS | Rejected requests must execute no commands. |
| Outside-lab target rejected | PASS | Rejected requests must execute no commands. |
| MCP schema rejects a Boolean port | PASS |  |
| Initial block succeeds | PASS |  |
| Repeated blocks make no additional changes | PASS |  |
| Block removed before concurrency test | PASS |  |
| Concurrent requests produce one change and seven no-ops | PASS | Batch duration: 50.47 ms |
| Exactly one port-23 rule exists | PASS |  |
| Concurrent-test rule removed | PASS |  |
| Repeated apply/remove cycles succeed | PASS |  |
| Unreachable probe returns a bounded failure | PASS | Elapsed: 3089.05 ms; project budget: 12000 ms |
| Final cleanup request succeeds | PASS |  |
| Final managed firewall state is empty | PASS |  |
| Every application response has one matching final audit record | FAIL | Checked 79 application request IDs. |

| Operation | Samples | Median ms | P95 ms | Maximum ms |
|---|---:|---:|---:|---:|
| repeat_no_change_ms | 20 | 8.131 | 9.05 | 9.342 |
| block_change_ms | 20 | 11.443 | 12.743 | 13.3 |
| allow_change_ms | 20 | 28.696 | 33.128 | 34.075 |

## Limitations

- Latency is measured, not graded against an approved requirement.
- Schema-level rejection is captured in client evidence, not the application audit, because the tool body is not invoked.
- This run does not test maximum rule capacity or crash recovery.

## Failures

- Audit: Every application response has one matching final audit record: Checked 79 application request IDs.
