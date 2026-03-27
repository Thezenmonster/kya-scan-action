# KYA Scan - MCP Security Check

Scan your MCP package dependencies for security issues on every push and PR. Checks the KYA abuse database and runs static analysis for install scripts, suspicious URLs, and metadata issues.

[![KYA Scan](https://agentscores.xyz/api/scan/badge?npm=mcp-trust-guard)](https://agentscores.xyz)

## Usage

Add to your workflow:

```yaml
name: KYA Security Scan
on: [push, pull_request]

jobs:
  kya-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Thezenmonster/kya-scan-action@v1
```

That's it. Every push and PR now scans your dependencies against the KYA abuse database and security scanner.

## Configuration

```yaml
- uses: Thezenmonster/kya-scan-action@v1
  with:
    # Minimum severity to fail the check (low, elevated, high, critical)
    fail-on: 'elevated'

    # Path to package.json
    package-json: './package.json'

    # Also scan devDependencies
    scan-dev-deps: 'false'
```

## What it checks

For each dependency in your package.json:

1. **KYA Abuse Database** - has this package been reported for malicious behaviour?
2. **Install scripts** - does the package run code on `npm install`?
3. **Suspicious URLs** - does the package contain hardcoded URLs to unknown endpoints?
4. **Metadata quality** - does the package have a source repo, licence, and description?
5. **Dependency count** - excessive dependencies increase attack surface

## Output

The action produces a GitHub Actions summary table showing every dependency, its scan score, risk level, and abuse status.

Issues that meet the `fail-on` threshold cause the check to fail. Dependencies with abuse reports always fail regardless of threshold.

## Example output

```
KYA Security Scan Results

Package              Score  Risk      Abuse
mcp-trust-guard      100    LOW       clean
@azure-devops/mcp    60     ELEVATED  1 report
express              100    LOW       clean

Issues Found:
@azure-devops/mcp - Risk: ELEVATED (score: 60)
  - [high] install_script: Package has 'preinstall' script
  - [high] suspicious_url: Package contains suspicious URL
```

## Free

No API key needed. No account required. Powered by [KYA (Know Your Agent)](https://agentscores.xyz).

Scan any package manually at [agentscores.xyz](https://agentscores.xyz).
