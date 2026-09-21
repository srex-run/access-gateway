#!/bin/sh

# Shared by production rendering and preflight. Ingress requires a DNS host;
# the external TLS port belongs to PUBLIC_URL, not to the Ingress host field.
load_public_url() {
  public_url=${PUBLIC_URL%/}
  case "$public_url" in https://*) ;; *) echo "PUBLIC_URL must be an HTTPS origin" >&2; return 2 ;; esac
  public_authority=${public_url#https://}
  case "$public_authority" in *[!A-Za-z0-9.:-]*) echo "PUBLIC_URL contains invalid hostname characters" >&2; return 2 ;; esac
  if ! printf '%s\n' "$public_authority" | grep -Eq '^[A-Za-z0-9.-]+(:[0-9]{1,5})?$'; then
    echo "PUBLIC_URL must be an HTTPS origin with a DNS host and optional port" >&2
    return 2
  fi
  public_host=$(printf '%s' "${public_authority%%:*}" | tr '[:upper:]' '[:lower:]')
  if [ "${#public_host}" -gt 253 ] || ! printf '%s\n' "$public_host" | grep -Eq '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$'; then
    echo "PUBLIC_URL hostname is invalid" >&2
    return 2
  fi
  case "$public_host" in *.invalid) echo "PUBLIC_URL must use a deployed DNS name" >&2; return 2 ;; esac
  if printf '%s\n' "$public_host" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
    echo "PUBLIC_URL must use a DNS name for Ingress" >&2
    return 2
  fi
  public_url=https://$public_host
  case "$public_authority" in
    *:*)
      public_port=${public_authority##*:}
      if [ "$public_port" -lt 1 ] || [ "$public_port" -gt 65535 ]; then
        echo "PUBLIC_URL port must be between 1 and 65535" >&2
        return 2
      fi
      public_url=$public_url:$public_port
      ;;
  esac
}
