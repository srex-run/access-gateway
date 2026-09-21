package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/srex-run/access-gateway/internal/bootstrap"
	"github.com/srex-run/access-gateway/internal/db"
	"github.com/srex-run/access-gateway/internal/secretstore"
)

func runBootstrap() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	databaseURL, err := secretstore.FromEnvironment("DATABASE_URL")
	if err != nil {
		return err
	}
	database, err := db.Open(ctx, db.Config{URL: databaseURL, MaxOpenConns: 1, MaxIdleConns: 1, ConnMaxLifetime: 5 * time.Minute, ConnMaxIdleTime: time.Minute})
	if err != nil {
		return err
	}
	defer database.Close()
	result, err := bootstrap.Initialize(ctx, database, bootstrap.Options{
		Username: os.Getenv("BOOTSTRAP_ADMIN_USERNAME"), Nickname: os.Getenv("BOOTSTRAP_ADMIN_NICKNAME"),
		PasswordFile: os.Getenv("BOOTSTRAP_ADMIN_PASSWORD_FILE"),
	})
	if err != nil {
		return err
	}
	if !result.Created {
		fmt.Println("Installation already initialized; skipping account initialization.")
		return nil
	}
	fmt.Printf("Initialized administrator %s. Initial password file: %s\n", result.Username, result.PasswordFile)
	return nil
}
