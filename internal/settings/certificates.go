package settings

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"k8s.io/apimachinery/pkg/util/validation"
)

type CertificateRequest struct {
	Purpose    string   `json:"purpose"`
	Protocol   string   `json:"protocol,omitempty"`
	Hosts      []string `json:"hosts"`
	ValidDays  int      `json:"valid_days"`
	AssetID    string   `json:"asset_id,omitempty"`
	TargetPort int      `json:"target_port,omitempty"`
	Target     string   `json:"target,omitempty"`
}

// Generated keys are returned once over the encrypted browser transport. They
// are persisted only if the administrator subsequently saves the settings.
type CertificateBundle struct {
	Certificate             string     `json:"certificate"`
	PrivateKey              string     `json:"private_key"`
	CA                      string     `json:"ca"`
	CertificateSHA256       string     `json:"certificate_sha256"`
	TargetCertificateSHA256 string     `json:"target_certificate_sha256,omitempty"`
	TargetHostKeys          []string   `json:"target_host_keys,omitempty"`
	SSHHostKey              string     `json:"ssh_host_key"`
	SSHPublicKey            string     `json:"ssh_public_key"`
	Archive                 string     `json:"archive"`
	ExpiresAt               *time.Time `json:"expires_at,omitempty"`
}

func GenerateAuditCertificate(input CertificateRequest) (CertificateBundle, error) {
	if input.AssetID != "" || input.TargetPort != 0 || input.Target != "" {
		return CertificateBundle{}, fmt.Errorf("资产参数仅用于一键接入配置")
	}
	if input.Protocol != "" {
		if input.Purpose != "target" {
			return CertificateBundle{}, fmt.Errorf("仅资产证书可以指定协议")
		}
		switch input.Protocol {
		case "mysql", "postgresql", "redis", "mongodb", "http":
		default:
			return CertificateBundle{}, fmt.Errorf("不支持的资产证书协议")
		}
	}
	if input.Purpose == "ssh" {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return CertificateBundle{}, fmt.Errorf("generate SSH identity: %w", err)
		}
		block, err := ssh.MarshalPrivateKey(key, "access-gateway")
		if err != nil {
			return CertificateBundle{}, fmt.Errorf("encode SSH identity: %w", err)
		}
		signer, err := ssh.NewSignerFromKey(key)
		if err != nil {
			return CertificateBundle{}, fmt.Errorf("encode SSH public identity: %w", err)
		}
		return CertificateBundle{SSHHostKey: string(pem.EncodeToMemory(block)), SSHPublicKey: string(ssh.MarshalAuthorizedKey(signer.PublicKey()))}, nil
	}
	if input.Purpose != "gateway" && input.Purpose != "target" {
		return CertificateBundle{}, fmt.Errorf("证书用途必须为 gateway、target 或 ssh")
	}
	if input.ValidDays == 0 {
		input.ValidDays = 365
	}
	if input.ValidDays < 1 || input.ValidDays > 825 || len(input.Hosts) == 0 || len(input.Hosts) > 32 {
		return CertificateBundle{}, fmt.Errorf("请填写 1 到 32 个域名或 IP，有效期为 1 到 825 天")
	}
	now := time.Now().UTC()
	expires := now.Add(time.Duration(input.ValidDays) * 24 * time.Hour)
	leaf := &x509.Certificate{Subject: pkix.Name{CommonName: "access-gateway " + input.Purpose},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: expires, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if input.Protocol == "mysql" {
		leaf.KeyUsage |= x509.KeyUsageKeyEncipherment
	}
	for _, host := range input.Hosts {
		host = strings.TrimSpace(host)
		if ip := net.ParseIP(host); ip != nil {
			leaf.IPAddresses = append(leaf.IPAddresses, ip)
		} else {
			if len(validation.IsDNS1123Subdomain(host)) != 0 {
				return CertificateBundle{}, fmt.Errorf("证书名称必须是域名或 IP，不能包含协议、路径或端口")
			}
			leaf.DNSNames = append(leaf.DNSNames, host)
		}
	}
	ca := &x509.Certificate{Subject: pkix.Name{CommonName: "access-gateway " + input.Purpose + " CA"}, NotBefore: leaf.NotBefore, NotAfter: expires,
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	for _, cert := range []*x509.Certificate{ca, leaf} {
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return CertificateBundle{}, fmt.Errorf("generate certificate serial: %w", err)
		}
		cert.SerialNumber = serial.Add(serial, big.NewInt(1))
	}
	caKey, err := generateAuditCertificateKey(input.Protocol)
	if err != nil {
		return CertificateBundle{}, fmt.Errorf("generate CA key: %w", err)
	}
	key, err := generateAuditCertificateKey(input.Protocol)
	if err != nil {
		return CertificateBundle{}, fmt.Errorf("generate server key: %w", err)
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caKey.Public(), caKey)
	if err != nil {
		return CertificateBundle{}, fmt.Errorf("generate CA: %w", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, key.Public(), caKey)
	if err != nil {
		return CertificateBundle{}, fmt.Errorf("generate server certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return CertificateBundle{}, fmt.Errorf("encode server key: %w", err)
	}
	defer clear(keyDER)
	sum := sha256.Sum256(der)
	bundle := CertificateBundle{CA: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		Certificate:       string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		PrivateKey:        string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
		CertificateSHA256: hex.EncodeToString(sum[:]), ExpiresAt: &expires}
	if input.Purpose == "target" {
		var archive bytes.Buffer
		writer := zip.NewWriter(&archive)
		files := []certificateArchiveFile{{"ca.crt", bundle.CA, 0600}, {"server.crt", bundle.Certificate, 0600}, {"server.key", bundle.PrivateKey, 0600}}
		if input.Protocol == "mysql" {
			files = append(files, mysqlCertificateFiles()...)
		}
		for _, file := range files {
			header := &zip.FileHeader{Name: file.name, Method: zip.Deflate}
			header.SetMode(file.mode)
			entry, err := writer.CreateHeader(header)
			if err != nil {
				return CertificateBundle{}, fmt.Errorf("create certificate archive: %w", err)
			}
			if _, err = entry.Write([]byte(file.content)); err != nil {
				return CertificateBundle{}, fmt.Errorf("write certificate archive: %w", err)
			}
		}
		if err := writer.Close(); err != nil {
			return CertificateBundle{}, fmt.Errorf("close certificate archive: %w", err)
		}
		bundle.Archive = base64.StdEncoding.EncodeToString(archive.Bytes())
		clear(archive.Bytes())
	}
	return bundle, nil
}

func generateAuditCertificateKey(protocol string) (crypto.Signer, error) {
	if protocol == "mysql" {
		return rsa.GenerateKey(rand.Reader, 2048)
	}
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
