package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/rs/zerolog"

	"github.com/srex-run/access-gateway/internal/gatewayagent"
)

func runSession(args []string, logger zerolog.Logger) error {
	flags := flag.NewFlagSet("session", flag.ContinueOnError)
	configPath := flags.String("config", gatewayagent.SessionConfigPath, "session grant file")
	stateDirectory := flags.String("state-dir", "/run/session/private", "private session state directory")
	lockFD := flags.Int("lock-fd", -1, "inherited session process lock")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || (*lockFD != -1 && *lockFD != 3) || !filepath.IsAbs(*stateDirectory) {
		return fmt.Errorf("invalid single-session agent arguments")
	}
	if *lockFD == 3 {
		lock := os.NewFile(3, "session process lock")
		if lock == nil {
			return fmt.Errorf("session process lock is missing")
		}
		defer lock.Close()
		if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			return fmt.Errorf("acquire inherited session process lock: %w", err)
		}
	} else {
		lock, err := gatewayagent.AcquireStateLock(filepath.Join(*stateDirectory, "agent"))
		if err != nil {
			return err
		}
		defer lock.Close()
	}
	cfg, err := gatewayagent.LoadSessionConfig(*configPath)
	if err != nil {
		return err
	}
	// A container/process restart must never reopen the same grant.
	started, err := os.OpenFile(filepath.Join(*stateDirectory, "started"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("session agent has already started or its state is unavailable: %w", err)
	}
	err = started.Sync()
	closeErr := started.Close()
	if err != nil || closeErr != nil {
		return fmt.Errorf("persist session launch marker: %w", errors.Join(err, closeErr))
	}
	directory, err := os.Open(*stateDirectory)
	if err != nil {
		return err
	}
	err = directory.Sync()
	closeErr = directory.Close()
	if err != nil || closeErr != nil {
		return fmt.Errorf("sync session launch directory: %w", errors.Join(err, closeErr))
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return gatewayagent.RunSessionAgent(ctx, cfg, *stateDirectory, logger)
}
