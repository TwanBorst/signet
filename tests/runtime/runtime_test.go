package runtime_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/TwanBorst/signet/internal/store"
	"github.com/TwanBorst/signet/internal/testutil"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestChartRuntimeManualSigning(t *testing.T) {
	base, path := os.Getenv("SIGNET_RUNTIME_URL"), os.Getenv("SIGNET_E2E_KUBECONFIG")
	if base == "" || path == "" {
		t.Skip("disposable chart deployment, SIGNET_RUNTIME_URL and kubeconfig required")
	}
	raw, err := clientcmd.LoadFromFile(path)
	if err != nil || !strings.HasPrefix(raw.CurrentContext, "kind-signet-") {
		t.Fatal("refusing non-disposable cluster")
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", path)
	if err != nil {
		t.Fatal(err)
	}
	scheme := runtime.NewScheme()
	cmapi.AddToScheme(scheme)
	corev1.AddToScheme(scheme)
	cl, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	httpClient := &http.Client{Timeout: 30 * time.Second}
	send := func(method, route string, input any, identity, origin string) (int, []byte) {
		t.Helper()
		var data []byte
		if input != nil {
			data, err = json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
		}
		req, err := http.NewRequest(method, base+route, bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		if identity != "" {
			req.Header.Set("x-auth-request-email", identity)
		}
		if method == "POST" {
			req.Header.Set("Origin", origin)
			req.Header.Set("X-Signet-CSRF", "1")
			req.Header.Set("Content-Type", "application/json")
		}
		response, err := httpClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, body
	}
	if status, _ := send("GET", "/api/me", nil, "", ""); status != 401 {
		t.Fatalf("missing identity: %d", status)
	}
	if status, _ := send("GET", "/api/me", nil, "one@example.com,two@example.com", ""); status != 401 {
		t.Fatalf("ambiguous identity: %d", status)
	}
	status, body := send("GET", "/api/requests?state=pending", nil, "operator@example.com", "")
	if status != 200 {
		t.Fatalf("queue %d %s", status, body)
	}
	var requests []store.Request
	if err := json.Unmarshal(body, &requests); err != nil {
		t.Fatal(err)
	}
	var r store.Request
	for _, req := range requests {
		if req.Namespace == "signet" && strings.HasPrefix(req.Name, "browser-check-") {
			r = req
			break
		}
	}
	if r.UID == "" {
		t.Fatal("apply tests/fixtures/browser-certificate.yaml and await pending request before runtime test")
	}
	status, csr := send("GET", "/api/requests/"+r.UID+"/csr", nil, "operator@example.com", "")
	if status != 200 {
		t.Fatalf("CSR %d %s", status, csr)
	}
	var cr cmapi.CertificateRequest
	if err := cl.Get(context.Background(), types.NamespacedName{Namespace: r.Namespace, Name: r.Name}, &cr); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(csr, cr.Spec.Request) {
		t.Fatal("downloaded CSR differs from cert-manager request")
	}
	cert, ca := testutil.Bundle(t, &cr)
	input := map[string]any{"version": r.Version, "certificate": cert, "chain": ca}
	if status, _ := send("POST", "/api/requests/"+r.UID+"/upload", input, "operator@example.com", "https://evil.example"); status != 403 {
		t.Fatalf("CSRF %d", status)
	}
	input["certificate"] = "-----BEGIN PRIVATE KEY-----\nrejected\n-----END PRIVATE KEY-----"
	if status, _ := send("POST", "/api/requests/"+r.UID+"/upload", input, "operator@example.com", "https://signet.example.com"); status != 400 {
		t.Fatalf("private key %d", status)
	}
	input["certificate"] = cert
	if status, body := send("POST", "/api/requests/"+r.UID+"/upload", input, "operator@example.com", "https://signet.example.com"); status != 200 {
		t.Fatalf("upload %d %s", status, body)
	}
	if status, _ := send("POST", "/api/requests/"+r.UID+"/upload", input, "operator@example.com", "https://signet.example.com"); status != 409 {
		t.Fatalf("duplicate upload %d", status)
	}
	delivered := false
	for deadline := time.Now().Add(2 * time.Minute); time.Now().Before(deadline); time.Sleep(time.Second) {
		var secret corev1.Secret
		err := cl.Get(context.Background(), types.NamespacedName{Namespace: "signet", Name: "browser-check"}, &secret)
		if err == nil && len(secret.Data["tls.key"]) > 0 && len(secret.Data["tls.crt"]) > 0 {
			status, body = send("GET", "/api/requests/"+r.UID, nil, "operator@example.com", "")
			var result store.Request
			if status == 200 && json.Unmarshal(body, &result) == nil && result.State == "issued" {
				delivered = true
				break
			}
		}
	}
	if !delivered {
		t.Fatal("runtime certificate was not delivered and confirmed")
	}
	status, body = send("GET", "/api/requests/"+r.UID+"/audit", nil, "operator@example.com", "")
	var audits []store.Audit
	if status != 200 || json.Unmarshal(body, &audits) != nil {
		t.Fatal("audit endpoint unavailable")
	}
	success, failure, download := false, false, false
	for _, a := range audits {
		if a.Actor == "operator@example.com" && a.Action == "upload" {
			success = success || a.Outcome == "success"
			failure = failure || a.Outcome == "failure"
		}
		if a.Actor == "operator@example.com" && a.Action == "csr.access" {
			download = true
		}
	}
	if !success || !failure || !download {
		t.Fatal("durable action/access audit missing")
	}
}
