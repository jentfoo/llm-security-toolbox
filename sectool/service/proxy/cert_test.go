package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertManager_NewGeneratesCA(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()

	// Create manager - should generate CA
	cm, err := NewCertManager(tempDir)
	require.NoError(t, err)
	require.NotNil(t, cm)

	// Verify CA files were created
	certPath := filepath.Join(tempDir, "ca.pem")
	keyPath := filepath.Join(tempDir, "ca-key.pem")

	_, err = os.Stat(certPath)
	require.NoError(t, err)

	_, err = os.Stat(keyPath)
	require.NoError(t, err)

	// Verify key file has restricted permissions
	keyInfo, _ := os.Stat(keyPath)
	assert.Equal(t, os.FileMode(0600), keyInfo.Mode().Perm())
}

func TestCertManager_LoadsExistingCA(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()

	// Create first manager to generate CA
	cm1, err := NewCertManager(tempDir)
	require.NoError(t, err)
	caCert1 := cm1.CACert()

	// Create second manager - should load existing CA
	cm2, err := NewCertManager(tempDir)
	require.NoError(t, err)
	caCert2 := cm2.CACert()

	// Should be the same certificate
	assert.Equal(t, caCert1.Raw, caCert2.Raw)
}

func TestCertManager_ErrorOnOrphanedCert(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()

	// Create only the cert file
	err := os.WriteFile(filepath.Join(tempDir, "ca.pem"), []byte("dummy"), 0644)
	require.NoError(t, err)

	_, err = NewCertManager(tempDir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key is missing")
}

func TestCertManager_ErrorOnOrphanedKey(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()

	// Create only the key file
	err := os.WriteFile(filepath.Join(tempDir, "ca-key.pem"), []byte("dummy"), 0600)
	require.NoError(t, err)

	_, err = NewCertManager(tempDir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "certificate is missing")
}

func TestCertManager_GetCertificate(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	cm, err := NewCertManager(tempDir)
	require.NoError(t, err)

	// Generate certificate for hostname
	cert, err := cm.GetCertificate("example.com")
	require.NoError(t, err)
	require.NotNil(t, cert)

	// Parse the certificate
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)

	// Verify certificate properties
	assert.Equal(t, "example.com", x509Cert.Subject.CommonName)
	assert.Contains(t, x509Cert.DNSNames, "example.com")
	assert.True(t, x509Cert.NotBefore.Before(time.Now()))
	assert.True(t, x509Cert.NotAfter.After(time.Now()))
}

func TestCertManager_GetCertificateCached(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	cm, err := NewCertManager(tempDir)
	require.NoError(t, err)

	// Get certificate twice
	cert1, err := cm.GetCertificate("example.com")
	require.NoError(t, err)

	cert2, err := cm.GetCertificate("example.com")
	require.NoError(t, err)

	// Should be the same certificate (cached)
	assert.Equal(t, cert1, cert2)
}

func TestCertManager_GetCertificateForIP(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	cm, err := NewCertManager(tempDir)
	require.NoError(t, err)

	// Generate certificate for IP address
	cert, err := cm.GetCertificate("192.168.1.1")
	require.NoError(t, err)
	require.NotNil(t, cert)

	// Parse the certificate
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)

	// Should have IP SAN, not DNS SAN
	assert.Empty(t, x509Cert.DNSNames)
	assert.Len(t, x509Cert.IPAddresses, 1)
	assert.Equal(t, "192.168.1.1", x509Cert.IPAddresses[0].String())
}

func TestCertManager_CertificateChain(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	cm, err := NewCertManager(tempDir)
	require.NoError(t, err)

	cert, err := cm.GetCertificate("example.com")
	require.NoError(t, err)

	// Should have certificate chain (leaf + CA)
	assert.Len(t, cert.Certificate, 2)

	// Verify chain
	leafCert, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(cert.Certificate[1])
	require.NoError(t, err)

	// Leaf should be signed by CA
	err = leafCert.CheckSignatureFrom(caCert)
	assert.NoError(t, err)
}

func TestCertManager_CertificateUsableForTLS(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	cm, err := NewCertManager(tempDir)
	require.NoError(t, err)

	cert, err := cm.GetCertificate("localhost")
	require.NoError(t, err)

	// Create TLS config with the certificate
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}

	// Should not panic
	assert.NotNil(t, tlsConfig.Certificates)
	assert.Len(t, tlsConfig.Certificates, 1)
}

func TestCertManager_CAProperties(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	cm, err := NewCertManager(tempDir)
	require.NoError(t, err)

	caCert := cm.CACert()
	require.NotNil(t, caCert)

	// Verify CA properties
	assert.True(t, caCert.IsCA)
	assert.NotEqual(t, x509.KeyUsage(0), caCert.KeyUsage&x509.KeyUsageCertSign)
	assert.Equal(t, "sectool CA", caCert.Subject.CommonName)
	assert.Contains(t, caCert.Subject.Organization, "sectool")
}
