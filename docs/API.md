# PromptScan API Documentation

PromptScan can be used as a Python library in addition to the `promptscan` CLI.
This page documents the public API exported from the `promptscan` package.

> Requires Python 3.9+ (see `pyproject.toml`).

## Public objects

```python
from promptscan import (
    AttackEngine,      # Orchestrates a full scan
    HTTPClient,        # Sends payloads to the target API
    ResponseAnalyzer,  # Detects vulnerabilities in a response
    RiskScorer,        # Calculates risk scores and severity
    ReportGenerator,   # Renders console / JSON / HTML reports
)
from promptscan.config import ScanConfig
from promptscan.analyzer import VulnerabilityMatch
```

## Quick start (running a full scan)

`AttackEngine.run_scan()` is asynchronous, so call it inside an event loop.

```python
import asyncio
from pathlib import Path

from promptscan import AttackEngine, ReportGenerator
from promptscan.config import ScanConfig

config = ScanConfig(
    target_url="https://api.example.com/chat",
    api_key="YOUR_API_KEY",          # optional -> sent as X-API-Key
    bearer_token=None,               # optional -> sent as Authorization: Bearer ...
    timeout=30,
    output_format="json",            # "console" | "json" | "html"
    output_file=Path("report.json"), # required for "json" / "html"
)

vulnerabilities, metadata = asyncio.run(AttackEngine(config).run_scan())

reporter = ReportGenerator()
reporter.generate_json_report(
    vulnerabilities, metadata, config.target_url, config.output_file
)
```

`run_scan()` returns a tuple `(vulnerabilities, metadata)`:

- `vulnerabilities` — `list[VulnerabilityMatch]`
- `metadata` — `dict` with keys `total_payloads`, `categories_tested`,
  `vulnerabilities_found`, `successful_attacks`, `failed_attacks`. If the scan
  could not run (unreachable target or no payloads), `metadata` contains an
  `error` key instead and `vulnerabilities` is empty — always check for this
  before treating the result as a clean report.

## `ScanConfig`

Dataclass holding scan settings. Validates on construction and raises
`ValueError` for an empty `target_url`, an invalid `output_format`, or a
`json`/`html` format without an `output_file`.

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `target_url` | `str` | — | Required. The endpoint that receives `POST {"message": <payload>}`. |
| `api_key` | `str \| None` | `None` | Sent as the `X-API-Key` header. |
| `bearer_token` | `str \| None` | `None` | Sent as `Authorization: Bearer ...`. |
| `timeout` | `int` | `30` | Per-request timeout in seconds. |
| `max_retries` | `int` | `3` | Retries on timeout / request error. |
| `payload_dir` | `Path \| None` | `None` | Custom payload directory; defaults to the bundled payloads. |
| `output_format` | `str` | `"console"` | `console`, `json`, or `html`. |
| `output_file` | `Path \| None` | `None` | Required for `json`/`html`. |
| `verbose` | `bool` | `False` | Verbose logging. |
| `custom_headers` | `dict[str, str] \| None` | `None` | Merged into request headers. |

## `VulnerabilityMatch`

Dataclass describing a single finding:

| Field | Type | Description |
|-------|------|-------------|
| `vulnerability_type` | `str` | e.g. `"System Prompt Leak"`. |
| `severity` | `str` | `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`. |
| `confidence` | `float` | `0.0`–`1.0`. |
| `evidence` | `str` | The text snippet that triggered detection. |
| `payload_used` | `str` | The payload that was sent (truncated). |
| `response_excerpt` | `str` | Surrounding response text. |

## Analyzing a single response

```python
from promptscan import ResponseAnalyzer

analyzer = ResponseAnalyzer()
response_data = {"success": True, "response_text": "You are an AI assistant ..."}
findings = analyzer.analyze_response(response_data, payload="...", payload_category="System Prompt Leak")
```

`response_data` must contain `success` (bool) and `response_text` (str), matching
the shape returned by `HTTPClient.send_payload()`.

## Scoring

```python
from promptscan import RiskScorer

scorer = RiskScorer()
score = scorer.calculate_risk_score(findings, total_payloads=36)   # 0.0 – 10.0
severity = scorer.get_severity_level(score)                        # CRITICAL/HIGH/MEDIUM/LOW/MINIMAL
recommendation = scorer.get_recommendation(score)
category_scores = scorer.calculate_category_scores(findings)
```

See [METHODOLOGY.md](METHODOLOGY.md) for the scoring algorithm details.
