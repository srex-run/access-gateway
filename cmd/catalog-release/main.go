package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/srex-run/access-gateway/internal/catalogrelease"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	flags := flag.NewFlagSet("catalog-release", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	catalogPath := flags.String("catalog", "", "control-plane gateway catalog JSON")
	targetsPath := flags.String("targets", "", "trusted target source JSON")
	outputDirectory := flags.String("output-dir", "", "private output directory")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	if strings.TrimSpace(*catalogPath) == "" || strings.TrimSpace(*targetsPath) == "" || strings.TrimSpace(*outputDirectory) == "" {
		fmt.Fprintln(os.Stderr, "usage: catalog-release --catalog FILE --targets FILE --output-dir ABSOLUTE_PATH")
		return 2
	}
	catalog, source, err := catalogrelease.Load(filepath.Clean(*catalogPath), filepath.Clean(*targetsPath))
	if err != nil {
		fmt.Fprintf(os.Stderr, "catalog-release: %v\n", err)
		return 1
	}
	bundle, err := catalogrelease.Build(catalog, source)
	if err != nil {
		fmt.Fprintf(os.Stderr, "catalog-release: validate inputs: %v\n", err)
		return 1
	}
	if err := catalogrelease.Write(*outputDirectory, bundle); err != nil {
		fmt.Fprintf(os.Stderr, "catalog-release: publish bundle: %v\n", err)
		return 1
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"gateway_id": bundle.Release.GatewayID, "release_id": bundle.Release.ReleaseID})
	return 0
}
