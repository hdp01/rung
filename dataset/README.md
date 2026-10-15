# Rung Sample Dataset

This folder contains small sanitized Kubernetes snapshot datasets for Rung.

- `sample-10.json` — a 10-entity sample graph (2 pods, 2 containers, 2 identities, 1 permission set, 1 volume, 1 node, 1 cluster).

Use it with:

```bash
curl -F file=@dataset/sample-10.json http://localhost:8000/ingest
```

or upload it from the Next.js dashboard.
