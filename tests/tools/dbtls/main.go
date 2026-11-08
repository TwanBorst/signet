// Generates disposable local test certificates; never use this CA in production.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func run() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("usage: dbtls <output-directory>")
	}
	out := os.Args[1]
	if err := os.MkdirAll(out, 0700); err != nil {
		return err
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Disposable Signet test CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "ca.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		return err
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "signet-test-db-e2a1"}, DNSNames: []string{"signet-test-db-e2a1", "signet-db.signet.svc.cluster.local"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err = x509.CreateCertificate(rand.Reader, cert, ca, &key.PublicKey, caKey)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "server.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		return err
	}
	der, err = x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(out, "server.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600)
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
