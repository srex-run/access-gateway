package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pressly/goose/v3"
	"github.com/rs/zerolog"

	"github.com/srex-run/access-gateway/internal/db"
	"github.com/srex-run/access-gateway/internal/secretstore"
	"github.com/srex-run/access-gateway/migrations"
)

func main() {
	logger := zerolog.New(os.Stdout).With().Timestamp().Str("service", "access-gateway-migrate").Logger()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	databaseURL, err := secretstore.FromEnvironment("DATABASE_URL")
	if err != nil {
		logger.Fatal().Err(err).Msg("load migration database secret failed")
	}
	database, err := db.Open(ctx, db.Config{
		URL: databaseURL, MaxOpenConns: 1, MaxIdleConns: 1,
		ConnMaxLifetime: 5 * time.Minute, ConnMaxIdleTime: time.Minute,
	})
	if err != nil {
		logger.Fatal().Err(err).Msg("open migration database failed")
	}
	defer database.Close()
	goose.SetBaseFS(migrations.GooseFS())
	if err := goose.SetDialect("postgres"); err != nil {
		logger.Fatal().Err(err).Msg("configure migration dialect failed")
	}
	command := "up"
	if len(os.Args) > 1 {
		command = os.Args[1]
	}
	switch command {
	case "up":
		err = goose.UpContext(ctx, database, ".")
	case "status":
		err = goose.StatusContext(ctx, database, ".")
	default:
		logger.Fatal().Str("command", command).Msg("migration command must be up or status")
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		logger.Fatal().Err(err).Str("command", command).Msg("migration command failed")
	}
	logger.Info().Str("command", command).Msg("migration command completed")
}
