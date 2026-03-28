# Advanced Upgrade (v1.0)

## What changed

- Target profiling feeds into payload priority decisions
- False-positive suppression based on contradictory signals
- Evidence snippets extracted from matched patterns
- Code execution risk scanner (shell, RCE, SQLI)
- Confidence-weighted severity prevents inflated scores
- Deduplication + posture-adaptive ordering
- Markdown executive report generator
- Richer JSON fields (`overall_confidence`, `attack_success`, `evidence`, `code_execution_risks`)

## Added files

- `core/target_profiler.py`
- `reports/markdown_report.py`

## Remaining enterprise features

- Authenticated web dashboard
- CI/CD pipeline integration
- SARIF / JUnit export support
- Regression benchmark datasets
- Distributed worker mode
- Secrets management layer
