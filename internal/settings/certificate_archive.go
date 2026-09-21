package settings

import (
	_ "embed"
	"io/fs"
)

//go:embed certificate-templates/mysql/mysql.cnf
var mysqlCertificateConfig string

//go:embed certificate-templates/mysql/install-mysql-tls.sh
var mysqlCertificateInstaller string

//go:embed certificate-templates/mysql/README.md
var mysqlCertificateReadme string

type certificateArchiveFile struct {
	name, content string
	mode          fs.FileMode
}

func mysqlCertificateFiles() []certificateArchiveFile {
	return []certificateArchiveFile{
		{"mysql.cnf", mysqlCertificateConfig, 0644},
		{"install-mysql-tls.sh", mysqlCertificateInstaller, 0700},
		{"README.md", mysqlCertificateReadme, 0644},
	}
}
