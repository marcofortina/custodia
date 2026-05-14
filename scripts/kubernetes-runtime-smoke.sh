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
  CUSTODIA_CONFIGMAP           Override release ConfigMap name.
  CUSTODIA_BOOTSTRAP_JOB_REQUIRED
                               Set to YES to require a completed chart bootstrap Job.

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

require_namespace() {
  if ! kubectl get namespace "$CUSTODIA_K8S_NAMESPACE" >/dev/null 2>&1; then
    die "namespace '$CUSTODIA_K8S_NAMESPACE' does not exist. This smoke is read-only and will not create namespaces or install Helm releases; complete docs/KUBERNETES_INSTALL.md first, or set CUSTODIA_K8S_NAMESPACE to the namespace that already contains the Custodia release."
  fi
}

rollout_status() {
  resource="$1"
  echo "kubernetes-runtime-smoke: waiting for $resource"
  kubectl -n "$CUSTODIA_K8S_NAMESPACE" rollout status "$resource" --timeout="$CUSTODIA_K8S_TIMEOUT"
}

wait_ready_pods() {
  selector="$1"
  description="$2"
  echo "kubernetes-runtime-smoke: waiting for $description pods to become Ready"
  kubectl -n "$CUSTODIA_K8S_NAMESPACE" wait --for=condition=Ready pod -l "$selector" --timeout="$CUSTODIA_K8S_TIMEOUT"
}

require_service_port() {
  service="$1"
  port_name="$2"
  if ! kubectl -n "$CUSTODIA_K8S_NAMESPACE" get "$service" -o jsonpath='{range .spec.ports[*]}{.name}{" "}{end}' | tr ' ' '\n' | grep -Fx "$port_name" >/dev/null; then
    die "$service is missing required port '$port_name'"
  fi
}

require_service_type() {
  service="$1"
  expected_type="$2"
  actual_type="$(kubectl -n "$CUSTODIA_K8S_NAMESPACE" get "$service" -o jsonpath='{.spec.type}')"
  if [ "$actual_type" != "$expected_type" ]; then
    die "$service has type '$actual_type'; expected '$expected_type'"
  fi
}

configmap_value() {
  configmap="$1"
  key="$2"
  kubectl -n "$CUSTODIA_K8S_NAMESPACE" get "$configmap" -o "jsonpath={.data.${key}}"
}

require_config_profile_coherence() {
  configmap="$1"
  profile="$(configmap_value "$configmap" CUSTODIA_PROFILE)"
  store_backend="$(configmap_value "$configmap" CUSTODIA_STORE_BACKEND)"
  rate_limit_backend="$(configmap_value "$configmap" CUSTODIA_RATE_LIMIT_BACKEND)"
  server_url="$(configmap_value "$configmap" CUSTODIA_SERVER_URL)"

  if [ "$profile" != "$CUSTODIA_K8S_PROFILE" ]; then
    die "$configmap profile '$profile' does not match CUSTODIA_K8S_PROFILE '$CUSTODIA_K8S_PROFILE'"
  fi
  if [ -z "$server_url" ]; then
    die "$configmap has an empty CUSTODIA_SERVER_URL"
  fi

  case "$profile:$store_backend:$rate_limit_backend" in
    lite:sqlite:memory) ;;
    full:postgres:valkey) ;;
    custom:*) ;;
    *) die "unsafe profile/backend wiring in $configmap: profile=$profile store=$store_backend rate_limit=$rate_limit_backend" ;;
  esac
}

wait_completed_jobs() {
  selector="$1"
  description="$2"
  jobs="$(kubectl_get_names job "$selector")"
  if [ -z "$jobs" ]; then
    if [ "${CUSTODIA_BOOTSTRAP_JOB_REQUIRED:-}" = "YES" ]; then
      die "missing required $description Job ($selector)"
    fi
    return 0
  fi
  printf '%s
' "$jobs" | while IFS= read -r job; do
    [ -n "$job" ] || continue
    echo "kubernetes-runtime-smoke: waiting for $job"
    kubectl -n "$CUSTODIA_K8S_NAMESPACE" wait --for=condition=complete "$job" --timeout="$CUSTODIA_K8S_TIMEOUT"
  done
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

  require_namespace

  if command -v helm >/dev/null 2>&1; then
    helm -n "$CUSTODIA_K8S_NAMESPACE" status "$CUSTODIA_HELM_RELEASE" >/dev/null
  else
    echo "kubernetes-runtime-smoke: helm not found; skipping helm status" >&2
  fi

  server_selector="app.kubernetes.io/instance=$CUSTODIA_HELM_RELEASE,app.kubernetes.io/component=server"
  signer_selector="app.kubernetes.io/instance=$CUSTODIA_HELM_RELEASE,app.kubernetes.io/component=signer"
  configmap_selector="app.kubernetes.io/instance=$CUSTODIA_HELM_RELEASE"
  bootstrap_selector="app.kubernetes.io/instance=$CUSTODIA_HELM_RELEASE,app.kubernetes.io/component=bootstrap"

  if [ -n "${CUSTODIA_CONFIGMAP:-}" ]; then
    configmap="configmap/$CUSTODIA_CONFIGMAP"
  else
    configmaps="$(require_labeled_resource configmap "$configmap_selector" "release ConfigMap")"
    configmap="$(printf '%s
' "$configmaps" | head -n 1)"
  fi
  require_config_profile_coherence "$configmap"

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
