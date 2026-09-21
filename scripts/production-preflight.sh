#!/bin/sh
set -eu

namespace=${NAMESPACE:-access-gateway}
case "$namespace" in ""|default|kube-system|*[!a-z0-9.-]*) echo "NAMESPACE is invalid" >&2; exit 2 ;; esac
PUBLIC_URL=${PUBLIC_URL:-}
. "$(dirname "$0")/public-url.sh"
load_public_url
command -v kubectl >/dev/null 2>&1 || { echo "kubectl is required" >&2; exit 2; }
command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 2; }

kubectl -n "$namespace" rollout status deployment/access-gateway --timeout=2m

for secret in access-gateway-secrets; do
  kubectl -n "$namespace" get secret "$secret" -o name >/dev/null
done
runtime_mode=$(kubectl -n "$namespace" get configmap/access-gateway-config -o jsonpath='{.data.GATEWAY_RUNTIME}')
[ "$runtime_mode" = "kubernetes" ] || { echo "GATEWAY_RUNTIME must be kubernetes" >&2; exit 1; }
deployed_public_url=$(kubectl -n "$namespace" get configmap/access-gateway-config -o jsonpath='{.data.PUBLIC_URL}')
[ "$deployed_public_url" = "$public_url" ] || { echo "PUBLIC_URL differs from the deployed platform origin" >&2; exit 1; }
agent_image=$(kubectl -n "$namespace" get configmap/access-gateway-config -o jsonpath='{.data.SESSION_AGENT_IMAGE}')
printf '%s\n' "$agent_image" | grep -Eq '@sha256:[0-9a-f]{64}$' || { echo "SESSION_AGENT_IMAGE must be digest pinned" >&2; exit 1; }
control_image=$(kubectl -n "$namespace" get deployment/access-gateway -o jsonpath='{.spec.template.spec.containers[?(@.name=="access-gateway")].image}')
[ "$agent_image" = "$control_image" ] || { echo "SESSION_AGENT_IMAGE must match the access-gateway image" >&2; exit 1; }
agent_node=$(kubectl -n "$namespace" get configmap/access-gateway-config -o jsonpath='{.data.SESSION_AGENT_NODE_NAME}')
kubectl get node "$agent_node" -o name >/dev/null

images=$(kubectl -n "$namespace" get deployment,statefulset,job -o jsonpath='{range .items[*].spec.template.spec.initContainers[*]}{.image}{"\n"}{end}{range .items[*].spec.template.spec.containers[*]}{.image}{"\n"}{end}')
while IFS= read -r image; do
  [ -z "$image" ] && continue
  if ! printf '%s\n' "$image" | grep -Eq '@sha256:[0-9a-f]{64}$'; then
    echo "running workload is not digest pinned: $image" >&2
    exit 1
  fi
done <<EOF
$images
EOF

kubectl -n "$namespace" get ingress/access-gateway -o name >/dev/null
ingress_host=$(kubectl -n "$namespace" get ingress/access-gateway -o jsonpath='{.spec.rules[0].host}')
[ "$ingress_host" = "$public_host" ] || { echo "Ingress hostname differs from PUBLIC_URL" >&2; exit 1; }
kubectl -n "$namespace" get networkpolicy/namespace-default-deny -o name >/dev/null
for resource in pods services secrets configmaps; do
  for verb in get create delete; do
    kubectl -n "$namespace" auth can-i "$verb" "$resource" --as="system:serviceaccount:$namespace:access-gateway" >/dev/null
  done
done
kubectl -n "$namespace" auth can-i list endpointslices.discovery.k8s.io --as="system:serviceaccount:$namespace:access-gateway" >/dev/null
kubectl -n "$namespace" auth can-i update configmaps --as="system:serviceaccount:$namespace:access-gateway" >/dev/null
kubectl -n "$namespace" get prometheusrule/access-gateway -o name >/dev/null
kubectl -n "$namespace" get servicemonitor/access-gateway -o name >/dev/null
kubectl -n "$namespace" get endpointslice -l kubernetes.io/service-name=access-gateway -o name
curl --fail --silent --show-error --max-time 5 "$public_url/healthz" >/dev/null
curl --fail --silent --show-error --max-time 5 "$public_url/readyz" >/dev/null
curl --fail --silent --show-error --max-time 5 "$public_url/" >/dev/null
echo "production preflight passed"
