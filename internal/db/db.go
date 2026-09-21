package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type Config struct {
	URL             string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
}

func Open(ctx context.Context, cfg Config) (*sql.DB, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("database URL is required")
	}
	if cfg.MaxOpenConns < 1 || cfg.MaxIdleConns < 1 || cfg.MaxIdleConns != cfg.MaxOpenConns {
		return nil, fmt.Errorf("invalid database pool limits: MaxIdleConns must equal MaxOpenConns")
	}
	if cfg.ConnMaxLifetime <= 0 || cfg.ConnMaxIdleTime <= 0 {
		return nil, fmt.Errorf("invalid database connection lifetime settings")
	}
	db, err := sql.Open("pgx", cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	db.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return db, nil
}
