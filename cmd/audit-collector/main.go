package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/srex-run/access-gateway/internal/operationaudit"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	endpoint := flag.String("endpoint", os.Getenv("PUBLIC_URL"), "control-plane HTTPS origin (defaults to PUBLIC_URL)")
	secretFile := flag.String("secret-file", "", "collector secret file (0600)")
	inputFile := flag.String("input", "", "normalized NDJSON audit segment; retained for replay")
	local := flag.Bool("allow-loopback-http", false, "allow loopback HTTP for development")
	flag.Parse()
	if *inputFile == "" || *secretFile == "" {
		return fmt.Errorf("--input and --secret-file are required")
	}
	info, err := os.Lstat(*secretFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 8192 {
		return fmt.Errorf("secret must be a regular file readable only by its owner, at most 8192 bytes")
	}
	secret, err := os.ReadFile(*secretFile)
	if err != nil {
		return fmt.Errorf("read collector secret file: %w", err)
	}
	collector, err := operationaudit.NewCollector(*endpoint, strings.TrimSpace(string(secret)), *local)
	clear(secret)
	if err != nil {
		return err
	}
	input, err := os.Open(*inputFile)
	if err != nil {
		return fmt.Errorf("open audit segment: %w", err)
	}
	defer input.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	count, err := collector.Forward(ctx, input)
	if err != nil {
		return fmt.Errorf("acknowledged %d records; source segment retained: %w", count, err)
	}
	fmt.Printf("acknowledged %d audit records; source segment retained\n", count)
	return nil
}
