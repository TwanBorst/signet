package pki_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	api "github.com/TwanBorst/signet/api/v1alpha1"
	"github.com/TwanBorst/signet/internal/pki"
	"github.com/TwanBorst/signet/internal/testutil"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

func TestDomainPolicyAndWeakKeys(t *testing.T) {
	cr, key := testutil.Request(t, "domains")
	uri, _ := url.Parse("spiffe://example.com/workload")
	for _, test := range []struct {
		name   string
		dns    []string
		ips    []net.IP
		emails []string
		uris   []*url.URL
		valid  bool
	}{
		{"single-level wildcard", []string{"*.example.com"}, nil, nil, nil, true},
		{"nested wildcard", []string{"*.nested.example.com"}, nil, nil, nil, true},
		{"multi-level wildcard", []string{"*.*.example.com"}, nil, nil, nil, false},
		{"suffix collision", []string{"evil-example.com"}, nil, nil, nil, false},
		{"mixed case", []string{"APP.example.com"}, nil, nil, nil, false},
		{"IP on DNS issuer", nil, []net.IP{net.ParseIP("10.0.0.1")}, nil, nil, false},
		{"email on DNS issuer", nil, nil, []string{"operator@example.com"}, nil, false},
		{"URI on DNS issuer", nil, nil, nil, []*url.URL{uri}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "app.example.com"},
				DNSNames: test.dns, IPAddresses: test.ips, EmailAddresses: test.emails, URIs: test.uris}, key)
			if err != nil {
				t.Fatal(err)
			}
			copy := cr.DeepCopy()
			copy.Spec.Request = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})
			_, err = pki.Template(copy, api.IssuerSpec{DNSNames: []string{"example.com"}})
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v err=%v", test.valid, err)
			}
		})
	}
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"app.example.com"}}, weak)
	if err != nil {
		t.Fatal(err)
	}
	cr.Spec.Request = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})
	if _, err := pki.Template(cr, api.IssuerSpec{}); err == nil {
		t.Fatal("accepted weak RSA key")
	}
}

func TestCertificateValidation(t *testing.T) {
	cr, _ := testutil.Request(t, "valid")
	cert, ca := testutil.Bundle(t, cr)
	for _, test := range []struct {
		name         string
		policy       api.IssuerSpec
		cert, chain  string
		now          time.Time
		valid, trust bool
	}{
		{"unverified", api.IssuerSpec{}, cert, ca, time.Now(), true, false},
		{"trusted", api.IssuerSpec{CABundle: ca, DNSNames: []string{"example.com"}}, cert, ca, time.Now(), true, true},
		{"private key", api.IssuerSpec{}, "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----", "", time.Now(), false, false},
		{"private key appended", api.IssuerSpec{}, cert + "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----", ca, time.Now(), false, false},
		{"oversized", api.IssuerSpec{}, strings.Repeat("x", pki.MaxPEM+1), "", time.Now(), false, false},
		{"expired", api.IssuerSpec{}, cert, ca, time.Now().Add(2 * time.Hour), false, false},
		{"future", api.IssuerSpec{}, cert, ca, time.Now().Add(-2 * time.Hour), false, false},
		{"wrong domain", api.IssuerSpec{DNSNames: []string{"elsewhere.com"}}, cert, ca, time.Now(), false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			trust, err := pki.Validate(cr, test.policy, test.cert, test.chain, test.now)
			if (err == nil) != test.valid || trust != test.trust {
				t.Fatalf("trust=%v err=%v", trust, err)
			}
		})
	}
	other, _ := testutil.Request(t, "wrong-key")
	if _, err := pki.Validate(other, api.IssuerSpec{}, cert, ca, time.Now()); err == nil {
		t.Fatal("accepted different public key")
	}
	mismatch := cr.DeepCopy()
	mismatch.Spec.Usages = []cmapi.KeyUsage{cmapi.UsageClientAuth}
	if _, err := pki.Validate(mismatch, api.IssuerSpec{}, cert, ca, time.Now()); err == nil {
		t.Fatal("accepted different usages")
	}
	_, otherCA := testutil.Bundle(t, other)
	if _, err := pki.Validate(cr, api.IssuerSpec{CABundle: otherCA}, cert, ca, time.Now()); err == nil {
		t.Fatal("accepted untrusted CA")
	}
	if _, err := pki.Validate(cr, api.IssuerSpec{}, cert, otherCA, time.Now()); err == nil {
		t.Fatal("accepted broken chain")
	}
}
func TestCSRValidation(t *testing.T) {
	cr, _ := testutil.Request(t, "csr")
	bad := cr.DeepCopy()
	bad.Spec.Request[len(bad.Spec.Request)/2] ^= 1
	if _, err := pki.Template(bad, api.IssuerSpec{}); err == nil {
		t.Fatal("accepted invalid CSR signature")
	}
	bad = cr.DeepCopy()
	bad.Spec.Request = []byte("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----")
	if _, err := pki.Template(bad, api.IssuerSpec{}); err == nil {
		t.Fatal("accepted private key as CSR")
	}
	for _, domain := range []string{"*.example.com", "Example.com", "bad..com", "-bad.com"} {
		if err := pki.ValidatePolicy(api.IssuerSpec{DNSNames: []string{domain}}); err == nil {
			t.Fatalf("accepted domain %q", domain)
		}
	}
}
