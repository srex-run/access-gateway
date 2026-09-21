package settings

import (
	"archive/zip"
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestAuditCertificateStorageRoundTrip(t *testing.T) {
	bundle, err := GenerateAuditCertificate(CertificateRequest{Purpose: "gateway", Hosts: []string{"gateway.test"}})
	if err != nil {
		t.Fatal(err)
	}
	config := Defaults()
	profile := AuditProfile{Name: "mysql", Protocol: "mysql", Port: 3306, Certificate: bundle.Certificate, GatewayCA: bundle.CA, TargetCA: bundle.CA}
	config.AuditProfiles = []AuditProfile{profile}
	secrets := Secrets{AuditProfiles: map[string]AuditKeys{"mysql": {PrivateKey: bundle.PrivateKey}}}
	runtimeSecrets := secrets
	stored := config.StoreAuditCertificates(&secrets)
	publicJSON, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(publicJSON, []byte("BEGIN CERTIFICATE")) || bytes.Contains(publicJSON, []byte("PRIVATE KEY")) {
		t.Fatal("PEM contents remain in plaintext settings")
	}
	if !reflect.DeepEqual(config.AuditProfiles[0], profile) || runtimeSecrets.AuditProfiles["mysql"].Certificate != "" {
		t.Fatal("storage preparation mutated a runtime snapshot")
	}
	privateJSON, err := json.Marshal(secrets)
	if err != nil {
		t.Fatal(err)
	}
	var decodedConfig Config
	var decodedSecrets Secrets
	if err := json.Unmarshal(publicJSON, &decodedConfig); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(privateJSON, &decodedSecrets); err != nil {
		t.Fatal(err)
	}
	decodedConfig.RestoreAuditCertificates(decodedSecrets)
	if !reflect.DeepEqual(decodedConfig.AuditProfiles[0], profile) || decodedSecrets.AuditProfiles["mysql"].PrivateKey != bundle.PrivateKey {
		t.Fatal("certificate bundle changed after storage round trip")
	}
	legacy := Defaults()
	legacy.AuditProfiles = []AuditProfile{profile}
	legacy.RestoreAuditCertificates(runtimeSecrets)
	if !reflect.DeepEqual(legacy.AuditProfiles[0], profile) {
		t.Fatal("legacy certificate fields were lost")
	}
	decodedConfig.AuditProfiles[0].TargetCA = ""
	cleared := decodedConfig.StoreAuditCertificates(&decodedSecrets)
	cleared.RestoreAuditCertificates(decodedSecrets)
	if cleared.AuditProfiles[0].TargetCA != "" || decodedSecrets.AuditProfiles["mysql"].TargetCA != "" {
		t.Fatal("cleared target CA was restored from stale encrypted settings")
	}
}

func TestGeneratedAuditCertificatesAndTargetArchive(t *testing.T) {
	for _, input := range []CertificateRequest{{Purpose: "gateway"}, {Purpose: "target"}, {Purpose: "target", Protocol: "mysql"}} {
		t.Run(input.Purpose+"/"+input.Protocol, func(t *testing.T) {
			input.Hosts = []string{"127.0.0.1", "gateway.test"}
			bundle, err := GenerateAuditCertificate(input)
			if err != nil {
				t.Fatal(err)
			}
			pair, err := tls.X509KeyPair([]byte(bundle.Certificate), []byte(bundle.PrivateKey))
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM([]byte(bundle.CA)) {
				t.Fatal("missing CA")
			}
			for _, host := range []string{"127.0.0.1", "gateway.test"} {
				if _, err := pair.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: host}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := pair.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "wrong.test"}); err == nil {
				t.Fatal("wrong hostname accepted")
			}
			if input.Protocol == "mysql" {
				key, ok := pair.PrivateKey.(*rsa.PrivateKey)
				if !ok || key.Size() < 256 || pair.Leaf.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
					t.Fatal("MySQL bundle must contain an RSA-2048 server key with encryption usage")
				}
			}
			if input.Purpose == "gateway" {
				return
			}
			data, err := base64.StdEncoding.DecodeString(bundle.Archive)
			if err != nil {
				t.Fatal(err)
			}
			archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]string{"ca.crt": bundle.CA, "server.crt": bundle.Certificate, "server.key": bundle.PrivateKey}
			if input.Protocol == "mysql" {
				want["mysql.cnf"], want["install-mysql-tls.sh"], want["README.md"] = mysqlCertificateConfig, mysqlCertificateInstaller, mysqlCertificateReadme
			}
			if len(archive.File) != len(want) {
				t.Fatal("unexpected archive contents")
			}
			directory := t.TempDir()
			for _, file := range archive.File {
				reader, err := file.Open()
				if err != nil {
					t.Fatal(err)
				}
				content, err := io.ReadAll(reader)
				reader.Close()
				mode := os.FileMode(0600)
				switch file.Name {
				case "mysql.cnf", "README.md":
					mode = 0644
				case "install-mysql-tls.sh":
					mode = 0700
				}
				if expected, ok := want[file.Name]; !ok || err != nil || string(content) != expected || file.Mode().Perm() != mode {
					t.Fatal("invalid asset archive file")
				}
				if err := os.WriteFile(filepath.Join(directory, file.Name), content, mode); err != nil {
					t.Fatal(err)
				}
			}
			if input.Protocol == "mysql" {
				testMySQLCertificateInstaller(t, directory, bundle)
			}
		})
	}
	for _, hosts := range [][]string{nil, {"https://target.test"}, {"target.test:3306"}, {"*.test"}, {"../secret"}} {
		if _, err := GenerateAuditCertificate(CertificateRequest{Purpose: "gateway", Hosts: hosts}); err == nil {
			t.Fatal("invalid certificate hostname accepted")
		}
	}
	for _, input := range []CertificateRequest{{Purpose: "target", Protocol: "unknown"}, {Purpose: "gateway", Protocol: "mysql"}, {Purpose: "ssh", Protocol: "mysql"}} {
		if _, err := GenerateAuditCertificate(input); err == nil {
			t.Fatal("invalid certificate protocol accepted")
		}
	}
}

func testMySQLCertificateInstaller(t *testing.T, directory string, bundle CertificateBundle) {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("shell installer requires sh")
	}
	installation := t.TempDir()
	certificates := filepath.Join(installation, "certificates")
	config := filepath.Join(installation, "config", "mysql.cnf")
	run := func(args ...string) ([]byte, error) {
		command := exec.Command("sh", append([]string{filepath.Join(directory, "install-mysql-tls.sh")}, args...)...)
		command.Env = append(os.Environ(), "MYSQL_TLS_DIR="+certificates, "MYSQL_TLS_CONFIG="+config,
			"MYSQL_TLS_USER="+strconv.Itoa(os.Getuid()), "MYSQL_TLS_GROUP="+strconv.Itoa(os.Getgid()))
		return command.CombinedOutput()
	}
	if output, err := run("--dry-run"); err != nil {
		t.Fatalf("installer dry-run failed: %v %s", err, output)
	}
	if _, err := os.Stat(certificates); !os.IsNotExist(err) {
		t.Fatal("installer dry-run modified the certificate directory")
	}
	if output, err := run(); err != nil {
		t.Fatalf("installer failed: %v %s", err, output)
	}
	for name, expected := range map[string]string{"ca.crt": bundle.CA, "server.crt": bundle.Certificate, "server.key": bundle.PrivateKey} {
		data, err := os.ReadFile(filepath.Join(certificates, name))
		if err != nil || string(data) != expected {
			t.Fatal("installer changed a certificate or key")
		}
	}
	key, err := os.Stat(filepath.Join(certificates, "server.key"))
	if err != nil || key.Mode().Perm() != 0600 {
		t.Fatal("installed MySQL private key is not restricted to its owner")
	}
	contents, err := os.ReadFile(config)
	if err != nil || string(contents) != strings.ReplaceAll(mysqlCertificateConfig, "/etc/mysql/access-gateway-tls", certificates) {
		t.Fatal("installed MySQL configuration does not reference the generated certificates")
	}
	if _, err := run(); err == nil {
		t.Fatal("installer overwrote an existing installation")
	}
	if after, err := os.ReadFile(config); err != nil || !bytes.Equal(contents, after) {
		t.Fatal("rejected installation modified MySQL configuration")
	}
}

func TestAuditSettingsPreservePrivateKeysAndResolveProfiles(t *testing.T) {
	bundle, err := GenerateAuditCertificate(CertificateRequest{Purpose: "gateway", Hosts: []string{"127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	config := Defaults()
	config.AuditProfiles = []AuditProfile{{Name: "mysql-audit", Port: 3306, Protocol: "mysql", Certificate: bundle.Certificate, GatewayCA: bundle.CA}}
	secrets := Secrets{}
	if err := config.ApplyAudit(Defaults(), &secrets, map[string]AuditKeyChanges{"mysql-audit": {PrivateKey: &bundle.PrivateKey}}); err != nil {
		t.Fatal(err)
	}
	registry, err := config.AuditRegistry(secrets)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := registry.Select(nil, 3306)
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := registry.Resolve(policy)
	if err != nil || proxy.PrivateKey != bundle.PrivateKey {
		t.Fatal("saved private key did not reach session policy")
	}
	encoded, _ := json.Marshal(config)
	if strings.Contains(string(encoded), "PRIVATE KEY") {
		t.Fatal("public settings exposed private key")
	}
	legacy := Defaults()
	legacy.AuditProfiles = nil
	if err := legacy.ApplyAudit(config, &secrets, nil); err != nil || len(legacy.AuditProfiles) != 1 || !secrets.Status().AuditProfiles["mysql-audit"].PrivateKey {
		t.Fatal("unrelated settings save lost profile")
	}
	replacement := config
	if err := replacement.ApplyAudit(config, &secrets, nil); err != nil {
		t.Fatal(err)
	}
	if secrets.AuditProfiles["mysql-audit"].PrivateKey != bundle.PrivateKey {
		t.Fatal("omitted key cleared")
	}
	replacement.AuditProfiles = []AuditProfile{}
	if err := replacement.ApplyAudit(config, &secrets, nil); err != nil || len(secrets.AuditProfiles) != 0 {
		t.Fatal("deleted profile retained key")
	}
	if err := replacement.ApplyAudit(config, &secrets, map[string]AuditKeyChanges{"unknown": {PrivateKey: &bundle.PrivateKey}}); err == nil {
		t.Fatal("unbound secret accepted")
	}
}

func TestGeneratedSSHAuditIdentity(t *testing.T) {
	bundle, err := GenerateAuditCertificate(CertificateRequest{Purpose: "ssh"})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey([]byte(bundle.SSHHostKey))
	if err != nil || string(ssh.MarshalAuthorizedKey(signer.PublicKey())) != bundle.SSHPublicKey {
		t.Fatal("SSH key pair does not match")
	}
	config := Defaults()
	config.AuditProfiles = []AuditProfile{{Name: "ssh-audit", Port: 22, Protocol: "ssh", TargetHostKeys: []string{bundle.SSHPublicKey}}}
	secrets := Secrets{}
	if err := config.ApplyAudit(Defaults(), &secrets, map[string]AuditKeyChanges{"ssh-audit": {SSHHostKey: &bundle.SSHHostKey}}); err != nil {
		t.Fatal(err)
	}
	if config.AuditProfiles[0].SSHHostPublicKey != bundle.SSHPublicKey {
		t.Fatal("uploaded private key did not produce public key")
	}
	if _, err := config.AuditRegistry(secrets); err != nil {
		t.Fatal(err)
	}
}
