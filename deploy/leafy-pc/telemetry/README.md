# GC telemetry collector — candidate, not deployed

Read [OI-02/03/04](../../../docs/rulepack/OI_02_03_04_TELEMETRY.md) for identity, limitations, transport gates and read-only acceptance commands.

- `exporter.py`: Python 3.11+ standard library, GET-only Docker Unix socket + internal cAdvisor, `/metrics`.
- `config.example.json`: placeholders deliberately rejected. Fill from observed GC inventory outside the repository.
- `compose.candidate.yml`: standalone candidate. No published host ports; no application services are modified. Image digests and transport remain review inputs.
- `verify.py`: offline snapshot identity/quality checks, exit 1 on failure. Never deploys or restarts anything.
- `tests/`: synthetic Docker fixtures, local temporary Unix socket transport, native M2 PromQL using `OI_PROMTOOL`.
- `source-copy-manifest.json`: SHA256 of ten selected nonsecret untracked reference files copied from the original worktree; those reference files are unchanged.

```sh
PYTHONDONTWRITEBYTECODE=1 OI_PROMTOOL=/path/to/promtool \
  python3 -m unittest discover -s deploy/leafy-pc/telemetry/tests -v
python3 -B deploy/leafy-pc/telemetry/verify.py --config /private/config.json /private/snapshot.prom
python3 -B deploy/leafy-pc/telemetry/verify.py --config /private/config.json --captures /private/captures.json
```

Without `OI_PROMTOOL`, native tests explicitly SKIP; they are not reported as PASS. Install test dependencies only in an isolated environment. Sandbox environments may require permission to bind the temporary **Unix socket**; the tests do not open a TCP port or access the real Docker daemon.
