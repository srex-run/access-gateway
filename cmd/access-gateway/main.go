package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/srex-run/access-gateway/internal/app"
	"github.com/srex-run/access-gateway/internal/config"
	"github.com/srex-run/access-gateway/internal/managementconsole"
	"github.com/srex-run/access-gateway/internal/observability"
)

func main() {
	logger := zerolog.New(os.Stdout).With().Timestamp().Str("service", "access-gateway").Logger()
	cfg, err := config.Load()
	if err != nil {
		logger.Fatal().Err(err).Msg("load configuration failed")
	}

	rootCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	shutdownTracing, err := observability.ConfigureTracing(rootCtx, observability.TracingConfig{
		ServiceName: cfg.OTELServiceName, OTLPEndpoint: cfg.OTLPTraceEndpoint,
	})
	if err != nil {
		logger.Fatal().Err(err).Msg("configure tracing failed")
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if shutdownErr := shutdownTracing(shutdownCtx); shutdownErr != nil {
			logger.Error().Err(shutdownErr).Msg("flush tracing failed")
		}
	}()
	components, err := app.Initialize(rootCtx, cfg, logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("build application failed")
	}
	defer components.Close()
	var handler http.Handler = components.HTTP.Container()
	if cfg.WebAssetsDir != "" {
		handler, err = managementconsole.NewApplicationHandler(handler, os.DirFS(cfg.WebAssetsDir))
		if err != nil {
			logger.Fatal().Err(err).Msg("load web assets failed")
		}
	}
	httpServer := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           otelhttp.NewHandler(handler, "access-gateway.http"),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		if runErr := components.Worker.Run(rootCtx); runErr != nil && !errors.Is(runErr, context.Canceled) {
			logger.Error().Err(runErr).Msg("worker stopped")
		}
	}()
	go func() {
		logger.Info().Str("addr", cfg.HTTPAddr).Msg("HTTP server started")
		if serveErr := httpServer.ListenAndServe(); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			logger.Error().Err(serveErr).Msg("HTTP server stopped unexpectedly")
			stop()
		}
	}()
	<-rootCtx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error().Err(err).Msg("HTTP server shutdown failed")
	}
}
