#!/usr/bin/env bash
# Copyright (c) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-only
#
# This file is part of Custodia.

set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/kubernetes-runtime-smoke.sh COMMAND

Commands:
  check-only      Verify local helper wiring without touching a cluster.
  cluster-check   Run a read-only Kubernetes runtime smoke against an installed release.
  help            Show this help.

cluster-check requires:
  export CUSTODIA_K8S_CONFIRM=YES

Optional environment:
  CUSTODIA_K8S_NAMESPACE       Kubernetes namespace. Default: custodia
  CUSTODIA_HELM_RELEASE        Helm release name. Default: custodia
  CUSTODIA_K8S_PROFILE         lite, full or custom. Default: full
  CUSTODIA_K8S_TIMEOUT         kubectl rollout timeout. Default: 180s
  CUSTODIA_SERVER_DEPLOYMENT   Override server Deployment name.
  CUSTODIA_SIGNER_DEPLOYMENT   Override signer Deployment name.

This helper is read-only. It does not create namespaces, install charts, exec into
pods, read Secrets or modify cluster state. The executable runbook is
  docs/KUBERNETES_RUNTIME_SMOKE.md
USAGE
}

die() {
  echo "kubernetes-runtime-smoke: $*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

require_confirm() {
  if [ "${CUSTODIA_K8S_CONFIRM:-}" != "YES" ]; then
    die "refusing cluster-check without CUSTODIA_K8S_CONFIRM=YES"
  fi
}

check_only() {
  test -f docs/KUBERNETES_RUNTIME_SMOKE.md || die "missing docs/KUBERNETES_RUNTIME_SMOKE.md"
  test -f scripts/kubernetes-runtime-smoke.sh || die "missing scripts/kubernetes-runtime-smoke.sh"
  need_cmd bash
  echo "kubernetes-runtime-smoke: check-only OK"
}

kubectl_get_names() {
  kind="$1"
  selector="$2"
  kubectl -n "$CUSTODIA_K8S_NAMESPACE" get "$kind" -l "$selector" -o name 2>/dev/null || true
}

require_labeled_resource() {
  kind="$1"
  selector="$2"
  description="$3"
  names="$(kubectl_get_names "$kind" "$selector")"
  if [ -z "$names" ]; then
    die "missing $description ($kind selector: $selector)"
  fi
  printf '%s\n' "$names"
}

rollout_status() {
  resource="$1"
  echo "kubernetes-runtime-smoke: waiting for $resource"
  kubectl -n "$CUSTODIA_K8S_NAMESPACE" rollout status "$resource" --timeout="$CUSTODIA_K8S_TIMEOUT"
}

cluster_check() {
  require_confirm
  need_cmd kubectl

  CUSTODIA_K8S_NAMESPACE="${CUSTODIA_K8S_NAMESPACE:-custodia}"
  CUSTODIA_HELM_RELEASE="${CUSTODIA_HELM_RELEASE:-custodia}"
  CUSTODIA_K8S_PROFILE="${CUSTODIA_K8S_PROFILE:-full}"
  CUSTODIA_K8S_TIMEOUT="${CUSTODIA_K8S_TIMEOUT:-180s}"

  case "$CUSTODIA_K8S_PROFILE" in
    lite|full|custom) ;;
    *) die "CUSTODIA_K8S_PROFILE must be lite, full or custom" ;;
  esac

  echo "kubernetes-runtime-smoke: context=$(kubectl config current-context 2>/dev/null || echo unknown)"
  echo "kubernetes-runtime-smoke: namespace=$CUSTODIA_K8S_NAMESPACE release=$CUSTODIA_HELM_RELEASE profile=$CUSTODIA_K8S_PROFILE"

  kubectl get namespace "$CUSTODIA_K8S_NAMESPACE" >/dev/null

  if command -v helm >/dev/null 2>&1; then
    helm -n "$CUSTODIA_K8S_NAMESPACE" status "$CUSTODIA_HELM_RELEASE" >/dev/null
  else
    echo "kubernetes-runtime-smoke: helm not found; skipping helm status" >&2
  fi

  server_selector="app.kubernetes.io/instance=$CUSTODIA_HELM_RELEASE,app.kubernetes.io/component=server"
  signer_selector="app.kubernetes.io/instance=$CUSTODIA_HELM_RELEASE,app.kubernetes.io/component=signer"

  if [ -n "${CUSTODIA_SERVER_DEPLOYMENT:-}" ]; then
    server_deployments="deployment.apps/$CUSTODIA_SERVER_DEPLOYMENT"
  else
    server_deployments="$(require_labeled_resource deployment "$server_selector" "server Deployment")"
  fi

  if [ -n "${CUSTODIA_SIGNER_DEPLOYMENT:-}" ]; then
    signer_deployments="deployment.apps/$CUSTODIA_SIGNER_DEPLOYMENT"
  else
    signer_deployments="$(require_labeled_resource deployment "$signer_selector" "signer Deployment")"
  fi

  printf '%s\n' "$server_deployments" | while IFS= read -r deployment; do
    [ -n "$deployment" ] && rollout_status "$deployment"
  done
  printf '%s\n' "$signer_deployments" | while IFS= read -r deployment; do
    [ -n "$deployment" ] && rollout_status "$deployment"
  done

  require_labeled_resource service "$server_selector" "server Service" >/dev/null
  require_labeled_resource service "$signer_selector" "signer Service" >/dev/null

  kubectl -n "$CUSTODIA_K8S_NAMESPACE" get pods -l "$server_selector" -o wide
  kubectl -n "$CUSTODIA_K8S_NAMESPACE" get pods -l "$signer_selector" -o wide

  if [ "$CUSTODIA_K8S_PROFILE" = "lite" ]; then
    require_labeled_resource pvc "$server_selector" "Lite SQLite PVC" >/dev/null
    kubectl -n "$CUSTODIA_K8S_NAMESPACE" get pvc -l "$server_selector"
  fi

  echo "kubernetes-runtime-smoke: OK"
}

command_name="${1:-help}"
case "$command_name" in
  check-only)
    check_only
    ;;
  cluster-check)
    cluster_check
    ;;
  help|-h|--help)
    usage
    ;;
  *)
    echo "unknown command: $command_name" >&2
    usage >&2
    exit 2
    ;;
esac
