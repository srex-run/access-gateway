package terminalclient

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// TLSMaterialError carries only allowlisted diagnostic categories. In
// particular, neither filesystem paths nor PEM/parser errors are transported.
type TLSMaterialError struct {
	File    string `json:"file"`
	Problem string `json:"problem"`
}

func (e *TLSMaterialError) valid() bool {
	if e == nil || (e.File != "ca" && e.File != "identity") {
		return false
	}
	switch e.Problem {
	case "permission_denied", "not_found", "read_failed", "invalid_pem":
		return true
	}
	return false
}

func (e *TLSMaterialError) Diagnostic() (reason, detail string) {
	if !e.valid() {
		return "client_tls_material_invalid", "native client TLS material check failed"
	}
	file := "session CA (ca.pem)"
	if e.File == "identity" {
		file = "session client certificate/key (client.pem)"
	}
	if e.Problem == "invalid_pem" {
		return "client_tls_" + e.File + "_invalid", "native client cannot parse " + file
	}
	problem := "read failed"
	switch e.Problem {
	case "permission_denied":
		problem = "permission denied by filesystem or sandbox"
	case "not_found":
		problem = "file not found"
	}
	return "client_tls_" + e.File + "_unreadable", "native client cannot read " + file + ": " + problem
}

func (e *TLSMaterialError) Error() string {
	reason, detail := e.Diagnostic()
	return detail + " (" + reason + ")"
}

func newClientDirectory() (string, error) {
	directory, err := os.MkdirTemp("", "gateway-terminal-")
	if err != nil {
		return "", err
	}
	// Use one canonical path for argv, environment, cwd and the sandbox.
	// In particular, macOS /tmp and /var are symlinks into /private.
	canonical, err := filepath.EvalSymlinks(directory)
	if err == nil {
		canonical, err = filepath.Abs(canonical)
	}
	if err != nil {
		_ = os.RemoveAll(directory)
		return "", err
	}
	return canonical, nil
}

// Run this in the helper after isolation, before the CLI can discard a useful
// file/PEM error and report only a generic TLS initialization failure.
func checkTLSMaterial(directory string, identity bool) *TLSMaterialError {
	read := func(name, role string) ([]byte, *TLSMaterialError) {
		data, err := os.ReadFile(filepath.Join(directory, name))
		if err == nil {
			return data, nil
		}
		problem := "read_failed"
		switch {
		case errors.Is(err, os.ErrPermission):
			problem = "permission_denied"
		case errors.Is(err, os.ErrNotExist):
			problem = "not_found"
		}
		return nil, &TLSMaterialError{File: role, Problem: problem}
	}
	ca, err := read("ca.pem", "ca")
	if err != nil {
		return err
	}
	if !x509.NewCertPool().AppendCertsFromPEM(ca) {
		return &TLSMaterialError{File: "ca", Problem: "invalid_pem"}
	}
	if identity {
		data, err := read("client.pem", "identity")
		if err != nil {
			return err
		}
		defer clear(data)
		if _, err := tls.X509KeyPair(data, data); err != nil {
			return &TLSMaterialError{File: "identity", Problem: "invalid_pem"}
		}
	}
	return nil
}

func readTLSMaterialError(reader io.Reader) error {
	var report TLSMaterialError
	if json.NewDecoder(io.LimitReader(reader, 1024)).Decode(&report) != nil || !report.valid() {
		return nil
	}
	return &report
}
