package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestDatabaseConfig(t *testing.T) {
	for _, name := range []string{"DATABASE_URL", "DATABASE_HOST", "DATABASE_NAME", "DATABASE_USERNAME", "DATABASE_PASSWORD", "DATABASE_PORT", "DATABASE_SSLROOTCERT"} {
		t.Setenv(name, "")
	}
	for _, tc := range []struct {
		name string
		env  map[string]string
		want bool
	}{
		{"url", map[string]string{"DATABASE_URL": "postgres://user:pass@db.example.com:5432/signet?sslmode=verify-full"}, true},
		{"url without TLS", map[string]string{"DATABASE_URL": "postgres://user:pass@db.example.com/signet?sslmode=disable"}, false},
		{"mixed modes", map[string]string{"DATABASE_URL": "postgres://db/signet?sslmode=verify-full", "DATABASE_HOST": "db"}, false},
		{"missing fields", map[string]string{"DATABASE_HOST": "db"}, false},
		{"invalid port", map[string]string{"DATABASE_HOST": "db", "DATABASE_NAME": "db", "DATABASE_USERNAME": "u", "DATABASE_PASSWORD": "p", "DATABASE_PORT": "65536"}, false},
		{"multiple hosts", map[string]string{"DATABASE_HOST": "db,other", "DATABASE_NAME": "db", "DATABASE_USERNAME": "u", "DATABASE_PASSWORD": "p"}, false},
		{"invalid CA", map[string]string{"DATABASE_HOST": "db", "DATABASE_NAME": "db", "DATABASE_USERNAME": "u", "DATABASE_PASSWORD": "p", "DATABASE_SSLROOTCERT": "/nonexistent/ca.crt"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for key, value := range tc.env {
				t.Setenv(key, value)
			}
			_, err := databaseConfig()
			if (err == nil) != tc.want {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
	t.Run("individual settings preserve special characters", func(t *testing.T) {
		t.Setenv("DATABASE_HOST", "2001:db8::1")
		t.Setenv("DATABASE_NAME", "/name/with spaces")
		t.Setenv("DATABASE_USERNAME", "user@name")
		t.Setenv("DATABASE_PASSWORD", "secret:@/?#%")
		t.Setenv("DATABASE_PORT", "5433")
		config, err := databaseConfig()
		if err != nil {
			t.Fatal(err)
		}
		c := config.ConnConfig
		if c.Host != "2001:db8::1" || c.Port != 5433 || c.Database != "/name/with spaces" || c.User != "user@name" || c.Password != "secret:@/?#%" || c.TLSConfig == nil || c.TLSConfig.InsecureSkipVerify {
			t.Fatal("individual settings were not preserved with verified TLS")
		}
	})
	t.Run("default port and suppressed credentials", func(t *testing.T) {
		t.Setenv("DATABASE_HOST", "db.example.com")
		t.Setenv("DATABASE_NAME", "signet")
		t.Setenv("DATABASE_USERNAME", "user")
		t.Setenv("DATABASE_PASSWORD", "sensitive-password")
		config, err := databaseConfig()
		if err != nil || config.ConnConfig.Port != 5432 {
			t.Fatalf("default port: %v", err)
		}
		t.Setenv("DATABASE_SSLROOTCERT", "/nonexistent/ca.crt")
		_, err = databaseConfig()
		if err == nil || strings.Contains(err.Error(), "sensitive-password") {
			t.Fatal("expected a sanitized configuration error")
		}
	})
	t.Run("individual settings use configured CA", func(t *testing.T) {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "db.example.com"},
			DNSNames: []string{"db.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
		if err != nil {
			t.Fatal(err)
		}
		certFile := filepath.Join(t.TempDir(), "ca.crt")
		if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("DATABASE_HOST", "db.example.com")
		t.Setenv("DATABASE_NAME", "signet")
		t.Setenv("DATABASE_USERNAME", "user")
		t.Setenv("DATABASE_PASSWORD", "password")
		t.Setenv("DATABASE_SSLROOTCERT", certFile)
		config, err := databaseConfig()
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		tls := config.ConnConfig.TLSConfig
		if tls == nil || tls.InsecureSkipVerify || tls.ServerName != "db.example.com" || tls.RootCAs == nil {
			t.Fatal("configured CA or hostname verification missing")
		}
		if _, err := cert.Verify(x509.VerifyOptions{Roots: tls.RootCAs, DNSName: tls.ServerName}); err != nil {
			t.Fatalf("configured CA did not verify server: %v", err)
		}
	})
}

func TestPublicOrigins(t *testing.T) {
	for _, tc := range []struct {
		name, single, multiple string
		want                   []string
	}{
		{"legacy", "https://signet.example.com", "", []string{"https://signet.example.com"}},
		{"multiple", "", `["https://signet.example.com","https://signet.example.org:8443"]`, []string{"https://signet.example.com", "https://signet.example.org:8443"}},
		{"missing", "", "", nil},
		{"both", "https://signet.example.com", `["https://signet.example.org"]`, nil},
		{"empty", "", `[]`, nil},
		{"null", "", `null`, nil},
		{"not JSON", "", "https://signet.example.com", nil},
		{"wrong type", "", `["https://signet.example.com",1]`, nil},
		{"duplicate", "", `["https://signet.example.com","https://signet.example.com"]`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := publicOrigins(tc.single, tc.multiple)
			if tc.want == nil {
				if err == nil {
					t.Fatal("invalid configuration accepted")
				}
			} else if err != nil || !slices.Equal(got, tc.want) {
				t.Fatalf("got %v, %v; want %v", got, err, tc.want)
			}
		})
	}
	for _, origin := range []string{"http://signet.example.com", "https://*.example.com", "https://signet.example.com/", "https://user@signet.example.com", "https://signet.example.com?", "https://signet.example.com#", "https://signet.example.com:0", "https://signet.example.com:65536", " https://signet.example.com", "https://signet.example.com,https://signet.example.org"} {
		t.Run(origin, func(t *testing.T) {
			if _, err := publicOrigins(origin, ""); err == nil {
				t.Fatal("unsafe origin accepted")
			}
		})
	}
}
