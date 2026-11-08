package testutil

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	api "github.com/TwanBorst/signet/api/v1alpha1"
	"github.com/TwanBorst/signet/internal/pki"
	"github.com/TwanBorst/signet/internal/store"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func DB(t *testing.T) *store.Store {
	t.Helper()
	uri := os.Getenv("SIGNET_TEST_DATABASE_URL")
	if uri == "" {
		t.Skip("SIGNET_TEST_DATABASE_URL not set; isolated PostgreSQL required")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, uri)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("signet_test_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(uri)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
			t.Error(err)
		}
		admin.Close(ctx)
	})
	s := &store.Store{Pool: pool}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return s
}
func Request(t *testing.T, uid string) (*cmapi.CertificateRequest, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "app.example.com"}, DNSNames: []string{"app.example.com"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{Namespace: "test", Name: uid, UID: types.UID(uid), CreationTimestamp: metav1.NewTime(time.Now().Add(-365 * 24 * time.Hour))},
		Spec: cmapi.CertificateRequestSpec{Request: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}),
			Duration: &metav1.Duration{Duration: time.Hour}, Usages: []cmapi.KeyUsage{cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment, cmapi.UsageServerAuth},
			IssuerRef: cmmeta.IssuerReference{Group: "signet.io", Kind: "SignetIssuer", Name: "manual"}},
	}, key
}
func Bundle(t *testing.T, cr *cmapi.CertificateRequest) (string, string) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	template, err := pki.Template(cr, api.IssuerSpec{})
	if err != nil {
		t.Fatal(err)
	}
	template.SerialNumber = big.NewInt(2)
	template.NotBefore = now.Add(-time.Minute)
	template.NotAfter = now.Add(59 * time.Minute)
	template.BasicConstraintsValid = true
	der, err := x509.CreateCertificate(rand.Reader, template, ca, template.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
}
func Ensure(t *testing.T, s *store.Store, cr *cmapi.CertificateRequest, p api.IssuerSpec, issuerUID string) {
	t.Helper()
	template, err := pki.Template(cr, p)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Ensure(context.Background(), store.Request{UID: string(cr.UID), Namespace: cr.Namespace, Name: cr.Name, IssuerKind: cr.Spec.IssuerRef.Kind,
		IssuerName: cr.Spec.IssuerRef.Name, DNSNames: template.DNSNames}, store.Snapshot{Request: *cr, Policy: p, IssuerUID: issuerUID}); err != nil {
		t.Fatal(err)
	}
}
