.PHONY: lint lint-all test test-all test-race test-integration fmt fmt-check kustomize run migrate-up migrate-status

.PHONY: web-dev web-build web-check run-web
.PHONY: dev dev-install dev-migrate dev-migrate-status dev-init dev-admin dev-check

# Sync dependencies with the lockfile, migrate, initialize once, then start both servers.
dev:
	node scripts/dev.mjs

# Optional maintenance commands; normal startup only needs make dev.
dev-install:
	npm --prefix apps/web ci --ignore-scripts --no-audit --no-fund

dev-migrate:
	node scripts/dev.mjs --migrate

dev-migrate-status:
	node scripts/dev.mjs --migrate-status

dev-init: dev-migrate
	node scripts/dev.mjs --initialize

dev-admin:
	node scripts/dev.mjs --account create --username admin --nickname Administrator --admin

dev-check:
	node scripts/dev.mjs --check

web-dev:
	npm --prefix apps/web run dev

web-build:
	npm --prefix apps/web run build

web-check:
	npm --prefix apps/web run lint
	npm --prefix apps/web test
	npm --prefix apps/web run build

run-web: web-build
	WEB_ASSETS_DIR=apps/web/dist $(MAKE) run

lint:
	go vet ./...

lint-all: lint

test:
	go test ./...

test-all: test

test-race:
	go test -race ./...

test-integration:
	POSTGRES_TEST_DSN="$${POSTGRES_TEST_DSN}" go test -count=1 -tags=integration ./internal/repository ./tests/integration

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

fmt-check:
	@test -z "$$(gofmt -l $$(find . -name '*.go' -not -path './vendor/*'))" || \
		{ gofmt -l $$(find . -name '*.go' -not -path './vendor/*'); exit 1; }

kustomize:
	kubectl kustomize deploy/kubernetes >/dev/null
	kubectl kustomize deploy/overlays/production >/dev/null

# Direct Go entry points require exported configuration and a migrated database.
run:
	go build -o bin/gateway-agent ./cmd/gateway-agent
	SESSION_AGENT_BINARY="$${SESSION_AGENT_BINARY:-$(abspath bin/gateway-agent)}" go run ./cmd/access-gateway

migrate-up:
	go run ./cmd/migrate up

migrate-status:
	go run ./cmd/migrate status
