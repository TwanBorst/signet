package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	api "github.com/TwanBorst/signet/api/v1alpha1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/issuer-lib/controllers/signer"
)

const MaxPEM = 128 * 1024

func blocks(data []byte, kind string) ([][]byte, error) {
	if len(data) == 0 || len(data) > MaxPEM {
		return nil, errors.New("PEM is empty or exceeds 128 KiB")
	}
	var result [][]byte
	for len(bytes.TrimSpace(data)) > 0 {
		data = bytes.TrimSpace(data)
		if !bytes.HasPrefix(data, []byte("-----BEGIN "+kind+"-----")) {
			return nil, fmt.Errorf("only %s PEM blocks are allowed", kind)
		}
		b, rest := pem.Decode(data)
		if b == nil || b.Type != kind || len(b.Headers) != 0 {
			return nil, errors.New("malformed PEM")
		}
		result = append(result, b.Bytes)
		data = rest
		if len(result) > 16 {
			return nil, errors.New("too many PEM blocks")
		}
	}
	return result, nil
}

func Certificates(data []byte) ([]*x509.Certificate, error) {
	b, err := blocks(data, "CERTIFICATE")
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	for _, der := range b {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, errors.New("malformed X.509 certificate")
		}
		certs = append(certs, c)
	}
	return certs, nil
}

func safeKey(key any) bool {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen() >= 2048 && k.E >= 65537
	case *ecdsa.PublicKey:
		return k.Curve.Params().BitSize >= 256
	case ed25519.PublicKey:
		return len(k) == ed25519.PublicKeySize
	default:
		return false
	}
}

func validateSAN(value []byte) error {
	var names []asn1.RawValue
	rest, err := asn1.Unmarshal(value, &names)
	if err != nil || len(rest) != 0 {
		return errors.New("malformed SAN extension")
	}
	for _, n := range names {
		if n.Class != asn1.ClassContextSpecific || n.IsCompound || (n.Tag != 1 && n.Tag != 2 && n.Tag != 6 && n.Tag != 7) {
			return errors.New("unsupported SAN type")
		}
	}
	return nil
}

func validDNS(name string, wildcard bool) bool {
	if wildcard && strings.HasPrefix(name, "*.") {
		name = name[2:]
	}
	if len(name) == 0 || len(name) > 253 || name != strings.ToLower(name) {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func ValidatePolicy(policy api.IssuerSpec) error {
	for _, domain := range policy.DNSNames {
		if !validDNS(domain, false) {
			return errors.New("allowlist domains must be lowercase DNS suffixes without wildcards")
		}
	}
	if policy.CABundle != "" {
		certs, err := Certificates([]byte(policy.CABundle))
		if err != nil {
			return err
		}
		for _, c := range certs {
			if !c.IsCA || !c.BasicConstraintsValid || c.KeyUsage&x509.KeyUsageCertSign == 0 || !safeKey(c.PublicKey) {
				return errors.New("trust bundle must contain CA certificates with safe public keys")
			}
		}
	}
	return nil
}

func Template(cr *cmapi.CertificateRequest, policy api.IssuerSpec) (*x509.Certificate, error) {
	if err := ValidatePolicy(policy); err != nil {
		return nil, err
	}
	b, err := blocks(cr.Spec.Request, "CERTIFICATE REQUEST")
	if err != nil || len(b) != 1 {
		return nil, errors.New("exactly one PEM CSR is required")
	}
	csr, err := x509.ParseCertificateRequest(b[0])
	if err != nil {
		return nil, errors.New("malformed CSR")
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, errors.New("invalid CSR signature")
	}
	if !safeKey(csr.PublicKey) {
		return nil, errors.New("unsupported or weak public key")
	}
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			if err := validateSAN(ext.Value); err != nil {
				return nil, err
			}
		}
	}
	if len(policy.DNSNames) != 0 && (len(csr.IPAddresses)+len(csr.EmailAddresses)+len(csr.URIs) != 0) {
		return nil, errors.New("DNS-restricted issuers cannot issue IP, email or URI SANs")
	}
	names := append([]string(nil), csr.DNSNames...)
	if csr.Subject.CommonName != "" {
		names = append(names, csr.Subject.CommonName)
	}
	for _, name := range names {
		if !validDNS(name, true) {
			return nil, errors.New("invalid DNS name or multi-level wildcard")
		}
		if len(policy.DNSNames) == 0 {
			continue
		}
		host := strings.TrimPrefix(name, "*.")
		allowed := false
		for _, d := range policy.DNSNames {
			allowed = allowed || host == d || strings.HasSuffix(host, "."+d)
		}
		if !allowed {
			return nil, errors.New("DNS name is outside issuer allowlist")
		}
	}
	details, err := signer.CertificateRequestObjectFromCertificateRequest(cr).GetCertificateDetails()
	if err != nil {
		return nil, errors.New("invalid requested key usages")
	}
	template, err := details.CertificateTemplate()
	if err != nil {
		return nil, errors.New("CSR extensions do not match CertificateRequest specification")
	}
	if details.Duration <= 0 {
		return nil, errors.New("duration must be positive")
	}
	return template, nil
}

func sanSet(c *x509.Certificate) []string {
	values := []string{}
	for _, s := range c.DNSNames {
		values = append(values, "dns:"+s)
	}
	for _, s := range c.EmailAddresses {
		values = append(values, "email:"+s)
	}
	for _, s := range c.IPAddresses {
		values = append(values, "ip:"+s.String())
	}
	for _, s := range c.URIs {
		values = append(values, "uri:"+s.String())
	}
	slices.Sort(values)
	return values
}

func Validate(cr *cmapi.CertificateRequest, policy api.IssuerSpec, certPEM, chainPEM string, now time.Time) (bool, error) {
	want, err := Template(cr, policy)
	if err != nil {
		return false, err
	}
	certs, err := Certificates([]byte(certPEM))
	if err != nil {
		return false, err
	}
	if chainPEM != "" {
		chain, err := Certificates([]byte(chainPEM))
		if err != nil {
			return false, err
		}
		certs = append(certs, chain...)
	}
	if len(certs) > 16 {
		return false, errors.New("certificate chain is too long")
	}
	leaf := certs[0]
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			if err := validateSAN(ext.Value); err != nil {
				return false, err
			}
		}
	}
	pub, err := x509.MarshalPKIXPublicKey(want.PublicKey)
	if err != nil || !bytes.Equal(pub, leaf.RawSubjectPublicKeyInfo) {
		return false, errors.New("certificate public key does not match CSR")
	}
	subject, err := asn1.Marshal(want.Subject.ToRDNSequence())
	if err != nil || !bytes.Equal(subject, leaf.RawSubject) {
		return false, errors.New("certificate subject does not match CSR")
	}
	if !slices.Equal(sanSet(want), sanSet(leaf)) {
		return false, errors.New("certificate SANs do not exactly match CSR")
	}
	if leaf.KeyUsage != want.KeyUsage || !equalUsages(leaf.ExtKeyUsage, want.ExtKeyUsage) || len(leaf.UnknownExtKeyUsage) != 0 {
		return false, errors.New("certificate usages do not match requested usages")
	}
	if leaf.IsCA != want.IsCA || !leaf.BasicConstraintsValid || len(leaf.UnhandledCriticalExtensions) != 0 {
		return false, errors.New("invalid certificate constraints or unsupported critical extensions")
	}
	if want.IsCA && (leaf.MaxPathLen != want.MaxPathLen || leaf.MaxPathLenZero != want.MaxPathLenZero) {
		return false, errors.New("CA path length does not match request")
	}
	details, _ := signer.CertificateRequestObjectFromCertificateRequest(cr).GetCertificateDetails()
	if leaf.NotAfter.Sub(leaf.NotBefore) > details.Duration+5*time.Minute {
		return false, errors.New("certificate validity exceeds requested duration")
	}
	for i, c := range certs {
		if now.Before(c.NotBefore) || !now.Before(c.NotAfter) || !c.NotAfter.After(c.NotBefore) {
			return false, errors.New("certificate is not currently valid")
		}
		if !safeKey(c.PublicKey) || c.SignatureAlgorithm == x509.MD5WithRSA || c.SignatureAlgorithm == x509.SHA1WithRSA || c.SignatureAlgorithm == x509.ECDSAWithSHA1 {
			return false, errors.New("unsafe certificate key or signature algorithm")
		}
		if i > 0 {
			if err := certs[i-1].CheckSignatureFrom(c); err != nil {
				return false, errors.New("chain is not ordered or signatures are invalid")
			}
		}
	}
	roots := x509.NewCertPool()
	verified := policy.CABundle != ""
	if verified {
		roots.AppendCertsFromPEM([]byte(policy.CABundle))
	} else if len(certs) > 1 {
		roots.AddCert(certs[len(certs)-1])
	} else {
		// No parent was supplied: matching is established, not issuer trust.
		if bytes.Equal(leaf.RawIssuer, leaf.RawSubject) && leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) != nil {
			return false, errors.New("invalid self-signature")
		}
		return false, nil
	}
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return false, errors.New("certificate chain or configured trust verification failed")
	}
	return verified, nil
}

func equalUsages(a, b []x509.ExtKeyUsage) bool {
	a = slices.Clone(a)
	b = slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}
