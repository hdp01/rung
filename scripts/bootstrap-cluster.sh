#!/usr/bin/env bash
# Stand up the Rung test cluster on any machine. Self-contained: no helm, no
# internet beyond image pulls. Produces the same RBAC + hardening Harsh's cluster
# has, so your collector/ingest produce a comparable graph.
#
# Prereqs: docker, kind (v0.33.0 recommended), kubectl.
set -euo pipefail
CTX=kind-graphhacks
FIX="$(cd "$(dirname "$0")/../fixtures/cluster" && pwd)"

echo "==> creating kind cluster 'graphhacks' (pulls ~1GB first time)"
kind create cluster --name graphhacks --wait 120s

echo "==> namespaces"
for ns in argocd certmgr monitoring jenkins; do
  kubectl --context $CTX create ns "$ns" >/dev/null 2>&1 || true
done

echo "==> real RBAC (Argo CD, cert-manager, kube-prometheus-stack, Jenkins)"
for f in rbac-argocd rbac-certmgr rbac-monitoring rbac-jenkins; do
  kubectl --context $CTX apply -f "$FIX/$f.yaml" >/dev/null
done

echo "==> hardening (PSA labels, a real token Secret, bind/escalate roles, webapps+staging ns)"
kubectl --context $CTX apply -f "$FIX/hardening.yaml" >/dev/null

echo "==> workloads with dangerous specs"
kubectl --context $CTX apply -f "$FIX/pods.yaml" >/dev/null
kubectl --context $CTX apply -f "$FIX/pods-argocd.yaml" >/dev/null

echo
echo "cluster ready (context: $CTX). sanity:"
kubectl --context $CTX get ns --no-headers | wc -l | xargs echo "  namespaces:"
kubectl --context $CTX get pods -A --no-headers | grep -vE 'kube-system|local-path' | wc -l | xargs echo "  app pods:"
echo
echo "now start FalkorDB:"
echo "  docker run -d --name falkordb -p 6380:6379 -p 3100:3000 falkordb/falkordb:latest"
echo "then: cd rung && uv sync && uv run rung collect --context $CTX -o data/snapshot.json"
