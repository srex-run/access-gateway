package main

import (
	"os"

	"github.com/rs/zerolog"

	"github.com/srex-run/access-gateway/internal/gatewayagent"
	"github.com/srex-run/access-gateway/internal/terminalclient"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "terminal-client" {
		os.Exit(terminalclient.ChildMain())
	}
	logger := zerolog.New(os.Stdout).With().Timestamp().Str("service", "gateway-agent").Logger()
	if len(os.Args) < 2 {
		logger.Fatal().Msg("gateway-agent requires a session or prepare-session command; session agents are started by the control plane")
	}
	var err error
	switch os.Args[1] {
	case "prepare-session":
		err = gatewayagent.PrepareSessionConfig("/source/session/session.json")
	case "session":
		err = runSession(os.Args[2:], logger)
	default:
		logger.Fatal().Msg("unsupported gateway agent command")
	}
	if err != nil {
		logger.Fatal().Err(err).Msg("session agent failed")
	}
}
