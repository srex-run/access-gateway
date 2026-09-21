#!/bin/sh
set -eu

manifest=${1:-}
if [ -z "$manifest" ] || [ ! -s "$manifest" ]; then
  echo "usage: verify-production-manifests.sh RENDERED_MANIFEST" >&2
  exit 2
fi

if grep -Eq 'REPLACE_|example\.invalid|192\.0\.2\.(0/24|10/32|20/32)|198\.51\.100\.0/24|203\.0\.113\.0/24|sha256:0{60}[1-5]' "$manifest"; then
  echo "production manifest still contains a placeholder value" >&2
  exit 1
fi

images=$(awk '/^[[:space:]]*(image|SESSION_AGENT_IMAGE):[[:space:]]*/ {sub(/^[[:space:]]*(image|SESSION_AGENT_IMAGE):[[:space:]]*/, ""); gsub(/"/, ""); print}' "$manifest")
if [ -z "$images" ]; then
  echo "production manifest contains no workload images" >&2
  exit 1
fi
while IFS= read -r image; do
  if ! printf '%s\n' "$image" | grep -Eq '^([^[:space:]@]+)@sha256:[0-9a-f]{64}$'; then
    echo "production image is not pinned by immutable sha256 digest: $image" >&2
    exit 1
  fi
done <<EOF
$images
EOF

for required in 'kind: Ingress' 'kind: NetworkPolicy' 'kind: PrometheusRule' 'kind: ServiceMonitor' 'kind: ServiceAccount' 'kind: Role' 'kind: RoleBinding' 'name: namespace-default-deny' 'GATEWAY_RUNTIME: kubernetes' 'SESSION_AGENT_IMAGE:' 'SESSION_AGENT_NODE_NAME:' 'PUBLIC_URL:'; do
  if ! grep -Fq "$required" "$manifest"; then
    echo "production manifest is missing required object marker: $required" >&2
    exit 1
  fi
done
