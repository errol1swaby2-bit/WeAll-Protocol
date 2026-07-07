# API contract map v1.5

`generated/api_contract_map_v1_5.json` is a generated static inventory of public FastAPI routes under `src/weall/api/routes_public_parts`.

It records, for each route:

- method;
- `/v1` path;
- source module/function/line;
- auth posture;
- error model posture;
- rate-limit posture;
- idempotency posture;
- cache posture;
- launch-matrix binding.

Truth boundary: this map is an audit and reviewer-readiness artifact. It does not replace runtime route tests, tx admission checks, or generated response schema vectors.

Regenerate with:

```bash
python3 scripts/gen_api_contract_map.py
```

Then verify with:

```bash
pytest tests/test_api_contract_map_v15.py
```
