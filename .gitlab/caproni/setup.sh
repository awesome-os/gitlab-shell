#!/usr/bin/env bash
# Writes tmp/caproni/config.yml so gitlab-sshd can run locally in Caproni edit mode.
#
# In the cluster, the container builds config.yml from the chart's config.yml.tpl when
# it starts. Nothing does that for the local process, so this script does it instead:
# it reads the template from the cluster, removes the template tags, and fills in
# the SSH host key paths.

set -euo pipefail

cd "$(dirname "$0")/../.."

namespace="${NAMESPACE:-gitlab}"
deployment="${DEPLOYMENT:-gitlab-gitlab-shell}"

get_deployment() {
  kubectl -n "$namespace" get deployment "$deployment" -o jsonpath="$1"
}

volume() {
  get_deployment "{.spec.template.spec.volumes[?(@.name==\"$1\")].$2}"
}

# Same env var and /etc/ssh default as the chart's config template.
keys_dir="$(get_deployment '{.spec.template.spec.containers[?(@.name=="gitlab-shell")].env[?(@.name=="KEYS_DIRECTORY")].value}')"
keys_dir="${keys_dir:-/etc/ssh}"

ssh_daemon="$(get_deployment '{.spec.template.spec.containers[?(@.name=="gitlab-shell")].env[?(@.name=="SSH_DAEMON")].value}')"
if [[ "$ssh_daemon" != "gitlab-sshd" ]]; then
  echo "error: deployment $namespace/$deployment runs sshDaemon=${ssh_daemon:-unset}, but edit mode needs gitlab-sshd." >&2
  echo "Set gitlab.gitlab-shell.sshDaemon: gitlab-sshd in caproni.local.yaml, then run caproni up." >&2
  exit 1
fi

configmap="$(volume shell-config configMap.name)"
if [[ -z "$configmap" ]]; then
  echo "error: deployment $namespace/$deployment has no shell-config ConfigMap volume." >&2
  echo "Set NAMESPACE or DEPLOYMENT if gitlab-shell runs elsewhere, or check its volumes with:" >&2
  echo "  kubectl -n $namespace get deployment $deployment -o yaml" >&2
  exit 1
fi

# Older charts keep the host keys in shell-init-secrets, newer charts in
# shell-host-keys. Check both to cover either chart version.
keys=""
for secret in \
  $(volume shell-init-secrets 'projected.sources[*].secret.name') \
  $(volume shell-host-keys secret.secretName); do
  # shellcheck disable=SC2016
  keys+="$(kubectl -n "$namespace" get secret "$secret" \
    -o go-template='{{range $k, $v := .data}}{{$k}}{{"\n"}}{{end}}' |
    { grep -E '^ssh_host_.*_key$' || true; } | tr '\n' ' ')"
done
if [[ -z "$keys" ]]; then
  echo "error: no SSH host keys (ssh_host_*_key) found for deployment $namespace/$deployment." >&2
  echo "To see which secrets the shell-init-secrets or shell-host-keys volume mounts, run:" >&2
  echo "  kubectl -n $namespace get deployment $deployment -o jsonpath='{.spec.template.spec.volumes}'" >&2
  exit 1
fi

mkdir -p tmp/caproni
kubectl -n "$namespace" get configmap "$configmap" -o jsonpath='{.data.config\.yml\.tpl}' |
  grep -v '{%' |
  awk -v keys="$keys" -v dir="$keys_dir" '
    { print }
    /^[[:space:]]*host_key_files:[[:space:]]*$/ {
      indent = $0
      sub(/[^[:space:]].*/, "", indent)
      n = split(keys, k, " ")
      for (i = 1; i <= n; i++) print indent "  - " dir "/" k[i]
    }
  ' >tmp/caproni/config.yml

echo "gitlab-sshd config for caproni edit mode: $PWD/tmp/caproni/config.yml"
