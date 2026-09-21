#!/bin/sh
set -eu

case "${1:-}" in
  ""|--dry-run) ;;
  *) printf '%s\n' 'Usage: sh install-mysql-tls.sh [--dry-run]' >&2; exit 2 ;;
esac

bundle_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
tls_dir=${MYSQL_TLS_DIR:-/etc/mysql/access-gateway-tls}
config_file=${MYSQL_TLS_CONFIG:-/etc/mysql/conf.d/access-gateway-tls.cnf}
mysql_user=${MYSQL_TLS_USER:-mysql}
mysql_group=${MYSQL_TLS_GROUP:-mysql}

for path in "$tls_dir" "$config_file"; do
  case "$path" in
    /*) ;;
    *) printf '%s\n' 'Certificate and configuration paths must be absolute.' >&2; exit 1 ;;
  esac
  case "$path" in
    *[!a-zA-Z0-9/._-]*|*/../*|*/..)
      printf '%s\n' 'Certificate and configuration paths contain unsupported characters.' >&2; exit 1 ;;
  esac
  if [ -e "$path" ] || [ -L "$path" ]; then
    printf 'Refusing to overwrite %s. Choose a new path or move the previous installation.\n' "$path" >&2
    exit 1
  fi
done

for file in ca.crt server.crt server.key; do
  if [ ! -f "$bundle_dir/$file" ]; then
    printf 'Missing bundle file: %s\n' "$file" >&2
    exit 1
  fi
done

if [ "${1:-}" = --dry-run ]; then
  printf 'Certificate directory: %s\nMySQL configuration: %s\nOwner: %s:%s\n' "$tls_dir" "$config_file" "$mysql_user" "$mysql_group"
  exit 0
fi

install -d -m 0750 -o "$mysql_user" -g "$mysql_group" "$tls_dir"
install -m 0644 -o "$mysql_user" -g "$mysql_group" "$bundle_dir/ca.crt" "$tls_dir/ca.crt"
install -m 0644 -o "$mysql_user" -g "$mysql_group" "$bundle_dir/server.crt" "$tls_dir/server.crt"
install -m 0600 -o "$mysql_user" -g "$mysql_group" "$bundle_dir/server.key" "$tls_dir/server.key"
install -d -m 0755 "$(dirname -- "$config_file")"
install -m 0644 /dev/null "$config_file"
printf '[mysqld]\nssl-ca=%s/ca.crt\nssl-cert=%s/server.crt\nssl-key=%s/server.key\n' "$tls_dir" "$tls_dir" "$tls_dir" > "$config_file"
printf '%s\n' 'Installed. Restart MySQL to load the certificates, then open a new access-gateway session.'
