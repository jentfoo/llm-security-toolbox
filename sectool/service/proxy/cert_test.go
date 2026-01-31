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

func TestNewCertManager(t *testing.T) {
	t.Parallel()

	t.Run("generates_new_ca", func(t *testing.T) {
		tempDir := t.TempDir()

		cm, err := newCertManager(tempDir)
		require.NoError(t, err)
		require.NotNil(t, cm)

		certPath := filepath.Join(tempDir, "ca.pem")
		keyPath := filepath.Join(tempDir, "ca-key.pem")

		_, err = os.Stat(certPath)
		require.NoError(t, err)

		_, err = os.Stat(keyPath)
		require.NoError(t, err)

		keyInfo, _ := os.Stat(keyPath)
		assert.Equal(t, os.FileMode(0600), keyInfo.Mode().Perm())
	})

	t.Run("loads_existing_ca", func(t *testing.T) {
		tempDir := t.TempDir()

		cm1, err := newCertManager(tempDir)
		require.NoError(t, err)
		caCert1 := cm1.CACert()

		cm2, err := newCertManager(tempDir)
		require.NoError(t, err)
		caCert2 := cm2.CACert()

		assert.Equal(t, caCert1.Raw, caCert2.Raw)
	})

	t.Run("error_on_orphaned_cert", func(t *testing.T) {
		tempDir := t.TempDir()

		err := os.WriteFile(filepath.Join(tempDir, "ca.pem"), []byte("dummy"), 0644)
		require.NoError(t, err)

		_, err = newCertManager(tempDir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key is missing")
	})

	t.Run("error_on_orphaned_key", func(t *testing.T) {
		tempDir := t.TempDir()

		err := os.WriteFile(filepath.Join(tempDir, "ca-key.pem"), []byte("dummy"), 0600)
		require.NoError(t, err)

		_, err = newCertManager(tempDir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "certificate is missing")
	})
}

func TestGetCertificate(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	cm, err := newCertManager(tempDir)
	require.NoError(t, err)

	t.Run("hostname_cert", func(t *testing.T) {
		cert, err := cm.GetCertificate("example.com")
		require.NoError(t, err)
		require.NotNil(t, cert)

		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		require.NoError(t, err)

		assert.Equal(t, "example.com", x509Cert.Subject.CommonName)
		assert.Contains(t, x509Cert.DNSNames, "example.com")
		assert.True(t, x509Cert.NotBefore.Before(time.Now()))
		assert.True(t, x509Cert.NotAfter.After(time.Now()))
	})

	t.Run("cached_cert", func(t *testing.T) {
		cert1, err := cm.GetCertificate("cached.example.com")
		require.NoError(t, err)

		cert2, err := cm.GetCertificate("cached.example.com")
		require.NoError(t, err)

		assert.Equal(t, cert1, cert2)
	})

	t.Run("ip_address_cert", func(t *testing.T) {
		cert, err := cm.GetCertificate("192.168.1.1")
		require.NoError(t, err)
		require.NotNil(t, cert)

		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		require.NoError(t, err)

		assert.Empty(t, x509Cert.DNSNames)
		assert.Len(t, x509Cert.IPAddresses, 1)
		assert.Equal(t, "192.168.1.1", x509Cert.IPAddresses[0].String())
	})

	t.Run("certificate_chain", func(t *testing.T) {
		cert, err := cm.GetCertificate("chain.example.com")
		require.NoError(t, err)

		assert.Len(t, cert.Certificate, 2)

		leafCert, err := x509.ParseCertificate(cert.Certificate[0])
		require.NoError(t, err)
		caCert, err := x509.ParseCertificate(cert.Certificate[1])
		require.NoError(t, err)

		err = leafCert.CheckSignatureFrom(caCert)
		assert.NoError(t, err)
	})

	t.Run("usable_for_tls", func(t *testing.T) {
		cert, err := cm.GetCertificate("tls.example.com")
		require.NoError(t, err)

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{*cert},
		}

		assert.NotNil(t, tlsConfig.Certificates)
		assert.Len(t, tlsConfig.Certificates, 1)
	})
}

func TestCACert(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	cm, err := newCertManager(tempDir)
	require.NoError(t, err)

	caCert := cm.CACert()
	require.NotNil(t, caCert)

	assert.True(t, caCert.IsCA)
	assert.NotEqual(t, x509.KeyUsage(0), caCert.KeyUsage&x509.KeyUsageCertSign)
	assert.Equal(t, "sectool CA", caCert.Subject.CommonName)
	assert.Contains(t, caCert.Subject.Organization, "sectool")
}
