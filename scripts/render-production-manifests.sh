#!/bin/sh
set -eu

require_value() {
  name=$1
  value=$(printenv "$name" 2>/dev/null || true)
  if [ -z "$value" ]; then
    echo "$name is required" >&2
    exit 2
  fi
}

require_pattern() {
  name=$1
  pattern=$2
  value=$(printenv "$name" 2>/dev/null || true)
  if ! printf '%s\n' "$value" | grep -Eq "$pattern"; then
    echo "$name has an invalid value" >&2
    exit 2
  fi
}

for name in \
  ACCESS_GATEWAY_IMAGE_DIGEST BUSYBOX_IMAGE_DIGEST PUBLIC_URL INGRESS_TLS_SECRET \
  INGRESS_NAMESPACE MONITORING_NAMESPACE POSTGRES_CIDR POSTGRES_PORT TARGET_CIDR \
  ACCESS_SOURCE_CIDR KUBERNETES_API_CIDR KUBERNETES_API_PORT EXTERNAL_HTTPS_CIDR \
  SESSION_AGENT_NODE_NAME ASSET_KEY_VERSION ADMIN_USER_IDS; do
  require_value "$name"
done

for name in ACCESS_GATEWAY_IMAGE_DIGEST BUSYBOX_IMAGE_DIGEST; do
  require_pattern "$name" '^sha256:[0-9a-f]{64}$'
  value=$(printenv "$name" 2>/dev/null || true)
  if printf '%s\n' "$value" | grep -Eq '^sha256:0{64}$'; then
    echo "$name must not be the all-zero digest" >&2
    exit 2
  fi
done
. "$(dirname "$0")/public-url.sh"
load_public_url
for name in INGRESS_TLS_SECRET INGRESS_NAMESPACE MONITORING_NAMESPACE; do
  require_pattern "$name" '^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$'
done
for name in ASSET_KEY_VERSION ADMIN_USER_IDS; do
  require_pattern "$name" '^[A-Za-z0-9][A-Za-z0-9._,-]*$'
done
for name in SESSION_AGENT_NODE_NAME; do
  require_pattern "$name" '^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$'
done
for name in POSTGRES_CIDR TARGET_CIDR ACCESS_SOURCE_CIDR KUBERNETES_API_CIDR EXTERNAL_HTTPS_CIDR; do
  require_pattern "$name" '^[0-9A-Fa-f:.]+/[0-9]{1,3}$'
done
for name in POSTGRES_PORT KUBERNETES_API_PORT; do
  require_pattern "$name" '^[0-9]{1,5}$'
  value=$(printenv "$name" 2>/dev/null || true)
  if [ "$value" -lt 1 ] || [ "$value" -gt 65535 ]; then
    echo "$name must be within 1-65535" >&2
    exit 2
  fi
done

command -v kubectl >/dev/null 2>&1 || { echo "kubectl is required" >&2; exit 2; }
workspace=$(mktemp -d)
trap 'rm -rf -- "$workspace"' EXIT HUP INT TERM
cp -R deploy "$workspace/deploy"

kustomization="$workspace/deploy/overlays/production/kustomization.yaml"
config="$workspace/deploy/overlays/production/production-config.yaml"
ingress="$workspace/deploy/overlays/production/ingress.yaml"
policies="$workspace/deploy/overlays/production/network-policies.yaml"

sed -i.bak \
  -e "s|sha256:0000000000000000000000000000000000000000000000000000000000000001|$ACCESS_GATEWAY_IMAGE_DIGEST|g" \
  -e "s|sha256:0000000000000000000000000000000000000000000000000000000000000005|$BUSYBOX_IMAGE_DIGEST|g" \
  "$kustomization"
sed -i.bak \
  -e "s|REPLACE_ASSET_KEY_VERSION|$ASSET_KEY_VERSION|g" \
  -e "s|REPLACE_ADMIN_USER_IDS|$ADMIN_USER_IDS|g" \
  -e "s|REPLACE_SESSION_NODE_NAME|$SESSION_AGENT_NODE_NAME|g" \
  -e "s|sha256:0000000000000000000000000000000000000000000000000000000000000001|$ACCESS_GATEWAY_IMAGE_DIGEST|g" \
  -e "s|https://access-gateway.example.invalid|$public_url|g" \
  "$config"
sed -i.bak \
  -e "s|access-gateway.example.invalid|$public_host|g" \
  -e "s|REPLACE_INGRESS_TLS_SECRET|$INGRESS_TLS_SECRET|g" \
  "$ingress"
sed -i.bak \
  -e "s|REPLACE_INGRESS_NAMESPACE|$INGRESS_NAMESPACE|g" \
  -e "s|REPLACE_MONITORING_NAMESPACE|$MONITORING_NAMESPACE|g" \
  -e "s|192.0.2.10/32|$POSTGRES_CIDR|g" \
  -e "s|192.0.2.0/24|$ACCESS_SOURCE_CIDR|g" \
  -e "s|192.0.2.20/32|$KUBERNETES_API_CIDR|g" \
  -e "s|198.51.100.0/24|$TARGET_CIDR|g" \
  -e "s|203.0.113.0/24|$EXTERNAL_HTTPS_CIDR|g" \
  -e "s|port: 15432|port: $POSTGRES_PORT|g" \
  -e "s|port: 16443|port: $KUBERNETES_API_PORT|g" \
  "$policies"

rendered="$workspace/production.yaml"
kubectl kustomize "$workspace/deploy/overlays/production" >"$rendered"
"$(dirname "$0")/verify-production-manifests.sh" "$rendered"
cat "$rendered"
