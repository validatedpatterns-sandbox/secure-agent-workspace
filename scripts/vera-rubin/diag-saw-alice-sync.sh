#!/usr/bin/env bash
set -uo pipefail
echo "=== app sync/health + operation phase + message ==="
oc get application saw-alice -n vp-gitops -o jsonpath='sync={.status.sync.status} health={.status.health.status}
opPhase={.status.operationState.phase}
opMsg={.status.operationState.message}
finishedAt={.status.operationState.finishedAt}{"\n"}' 2>&1
echo
echo "=== which resources are NOT Synced ==="
oc get application saw-alice -n vp-gitops -o jsonpath='{range .status.resources[*]}{.kind}/{.name}={.status}  {end}{"\n"}' 2>&1 | tr ' ' '\n' | grep -vE "=Synced$" | grep -v '^$' | head
echo
echo "=== did the live installer CM get Replace annotation / is SSA working now? ==="
oc get configmap alice-installer -n saw-alice -o jsonpath='annotations={.metadata.annotations}
managedFields={range .metadata.managedFields[*]}{.manager}({.operation}) {end}{"\n"}' 2>&1
echo
echo "=== last sync result detail (per-resource message) ==="
oc get application saw-alice -n vp-gitops -o jsonpath='{range .status.operationState.syncResult.resources[?(@.status=="SyncFailed")]}{.kind}/{.name}: {.message}{"\n"}{end}' 2>&1
