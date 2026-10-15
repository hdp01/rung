# Rung Sample Datasets

Small sanitized Kubernetes snapshot datasets for testing Rung.

| File | Entity count | Purpose |
|---|---:|---|
| `sample-empty.json` | 1 | Empty/minimal edge case |
| `sample-small.json` | 6 | Small non-admin workload |
| `sample-10.json` | 10 | Balanced demo dataset |
| `sample-secure.json` | 11 | Restricted PSA, no dangerous permissions |
| `sample-attack-chain.json` | 7 | Privileged hostPID/hostPath plus cluster-admin chain |
| `sample-scale.json` | 45 | Larger 10-team workload |

Use one with:

```bash
curl -F file=@dataset/sample-attack-chain.json http://localhost:8000/ingest
```

or upload it from the Next.js dashboard.
