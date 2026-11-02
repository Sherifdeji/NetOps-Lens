# AGENTS.md

## Project: NetOps Lens

NetOps Lens is an AI-powered network configuration change
investigation application being developed for the Meta Global
AI Developer Hackathon.

Its purpose is to help network engineers identify connectivity
regressions and investigate proposed network changes before
deployment.

## Technology Stack

- Python 3.14
- Batfish running locally through Docker
- Pybatfish
- Muse Spark through Meta Model API
- Streamlit
- Pytest
- Pydantic where structured validation is useful

## Existing Verified Implementation

The following have already been tested successfully:

1. Batfish runs in Docker.
2. Python connects through Pybatfish.
3. Two Cisco IOS router configurations parse successfully.
4. Baseline snapshot initializes correctly.
5. Virtual traceroute confirms connectivity.
6. Removing a static route creates NO_ROUTE.
7. Differential reachability identifies the regression.

Existing files:

- test_batfish.py
- test_diff.py
- lab/baseline/configs/
- lab/proposed/configs/

Preserve these working files and fixtures.

## Engineering Principles

- Use typed Python.
- Avoid unnecessary abstractions and dependencies.
- Follow DRY and KISS.
- Keep functions focused and testable.
- Handle errors explicitly.
- Do not use Any unnecessarily.
- Return structured, serializable analysis results.
- Keep raw Pandas DataFrames within the analysis layer.

## Network Analysis Rules

- Use real vendor configuration files supported by Batfish.
- Check parsing and snapshot health before trusting results.
- Never fabricate network analysis findings.
- Distinguish confirmed regressions from inconclusive results.
- Do not claim that untested traffic is safe.

## AI Agent Rules

- Use actual Muse Spark API tool calling.
- Validate model-generated tool arguments.
- Implement bounded tool-calling loops.
- Maintain structured evidence records.
- Reject fabricated or unsupported evidence references.
- Python determines the final assessment status.

## Safety Constraints

- V1 is read-only.
- Never modify live network devices.
- Preserve baseline snapshots.
- Keep experiments isolated.
- Never expose API keys or secrets.
- Keep .env out of Git.

## Development Workflow

- Inspect existing code before modifying it.
- Work incrementally according to the approved implementation plan.
- Explain significant architectural decisions.
- Run relevant tests after modifications.
- Do not silently skip failing tests.
- Report changed files, tests and outstanding issues.
- Ask before making major architectural changes.
