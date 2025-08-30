# SAFE-T1103: Fake Tool Invocation (Function Spoofing)

## Description
Adversaries may forge JSON messages that mimic legitimate MCP function-call messages.  
If the host system does not strictly validate tool invocations against its registered manifest, it may execute a tool that was never offered, enabling arbitrary or malicious actions.

## Tactic
- **ATK-TA0002: Execution** (primary)
- **ATK-TA0005: Defence Evasion** (secondary, if spoofed calls are used to bypass security checks)
- **ATK-TA0007: Discovery** (secondary, if attackers first probe for existing tool names and craft spoofed calls accordingly)

## Technique ID
- **SAFE-T1103**

## Attack Scenario
Example of a legitimate MCP tool invocation:
```json
{
  "type": "function_call",
  "name": "search_files",
  "arguments": { "query": "report.pdf" }
}
