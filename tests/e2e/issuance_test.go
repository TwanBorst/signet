package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	api "github.com/TwanBorst/signet/api/v1alpha1"
	"github.com/TwanBorst/signet/internal/controller"
	"github.com/TwanBorst/signet/internal/httpapi"
	"github.com/TwanBorst/signet/internal/store"
	"github.com/TwanBorst/signet/internal/testutil"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

func eventually(t *testing.T, description string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatal("timed out: " + description)
}

// This test must only target a disposable cluster. It installs no controller
// into the user's cluster and consumes private keys only to verify ownership.
func TestCertManagerManualIssuanceAndRenewal(t *testing.T) {
	path := os.Getenv("SIGNET_E2E_KUBECONFIG")
	if path == "" {
		t.Skip("SIGNET_E2E_KUBECONFIG not set; disposable cert-manager cluster required")
	}

	cfg, err := clientcmd.BuildConfigFromFlags("", path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := clientcmd.LoadFromFile(path)
	if err != nil || !strings.HasPrefix(raw.CurrentContext, "kind-signet-") {
		t.Fatal("refusing non-Signet disposable cluster")
	}
	scheme := runtime.NewScheme()
	ctrl.SetLogger(zap.New())
	cmapi.AddToScheme(scheme)
	api.AddToScheme(scheme)
	corev1.AddToScheme(scheme)
	cl, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	db := testutil.DB(t)
	ctx := context.Background()
	ns := fmt.Sprintf("signet-e2e-%d", time.Now().UnixNano())
	if err := cl.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cl.Delete(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}) })

	instances := []controller.Instance{{Kind: "SignetIssuer", Namespace: ns, Name: "manual"}, {Kind: "SignetClusterIssuer", Name: ns}}
	var c *controller.Controller
	var stop context.CancelFunc
	var done chan error
	start := func() {
		runctx, cancel := context.WithCancel(context.Background())
		stop = cancel
		mgr, err := ctrl.NewManager(cfg, ctrl.Options{Scheme: scheme, Metrics: server.Options{BindAddress: "0"}, Controller: config.Controller{SkipNameValidation: new(true)}})
		if err != nil {
			t.Fatal(err)
		}
		c = &controller.Controller{Store: db, Instances: instances}
		if err := c.Setup(runctx, mgr); err != nil {
			t.Fatal(err)
		}
		done = make(chan error, 1)
		go func() { done <- mgr.Start(runctx) }()
	}
	shutdown := func() {
		stop()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(20 * time.Second):
			t.Fatal("manager did not shut down")
		}
	}
	start()
	t.Cleanup(func() { shutdown() })
	if err := cl.Create(ctx, &api.SignetIssuer{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "manual"}, Spec: api.IssuerSpec{DNSNames: []string{"example.com"}}}); err != nil {
		t.Fatal(err)
	}
	if err := cl.Create(ctx, &api.SignetClusterIssuer{ObjectMeta: metav1.ObjectMeta{Name: ns}, Spec: api.IssuerSpec{DNSNames: []string{"example.com"}}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cl.Delete(ctx, &api.SignetClusterIssuer{ObjectMeta: metav1.ObjectMeta{Name: ns}}) })

	for _, inst := range instances {
		t.Run(inst.Kind, func(t *testing.T) {
			name := strings.ToLower(inst.Kind)
			certificate := &cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Spec: cmapi.CertificateSpec{
				SecretName: name, CommonName: "app.example.com", DNSNames: []string{"app.example.com"},
				Duration: &metav1.Duration{Duration: time.Hour}, RenewBefore: &metav1.Duration{Duration: 20 * time.Minute},
				Usages:    []cmapi.KeyUsage{cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment, cmapi.UsageServerAuth},
				IssuerRef: cmmeta.IssuerReference{Group: "signet.io", Kind: inst.Kind, Name: inst.Name},
			}}
			if err := cl.Create(ctx, certificate); err != nil {
				t.Fatal(err)
			}
			pending := func(previous string) store.Request {
				var result store.Request
				eventually(t, "approved CSR in durable pending queue", func() bool {
					requests, err := db.List(ctx, ns, "pending", "")
					if err != nil {
						return false
					}
					for _, r := range requests {
						if strings.HasPrefix(r.Name, name+"-") && r.UID != previous && c.Live(ctx, r) == nil {
							result = r
							return true
						}
					}
					return false
				})
				return result
			}
			upload := func(r store.Request) {
				snap, err := db.Access(ctx, r.UID, "test:operator", "E2E external signing")
				if err != nil {
					t.Fatal(err)
				}
				cert, ca := testutil.Bundle(t, &snap.Request)
				input, _ := json.Marshal(map[string]any{"certificate": cert, "chain": ca, "version": r.Version})
				h := &httpapi.Server{Store: db, AuthHeader: "x-auth-request-email", Origin: "https://signet.example.com", UI: http.NotFoundHandler(), Live: c.Live}
				request := httptest.NewRequest("POST", "/api/requests/"+r.UID+"/upload", bytes.NewReader(input))
				request.Header.Set("x-auth-request-email", "operator@example.com")
				request.Header.Set("Origin", "https://signet.example.com")
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set("X-Signet-CSRF", "1")
				w := httptest.NewRecorder()
				h.ServeHTTP(w, request)
				if w.Code != 200 {
					t.Fatalf("upload: %d %s", w.Code, w.Body)
				}
			}
			first := pending("")
			var noSecret corev1.Secret
			if err := cl.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &noSecret); err == nil {
				t.Fatal("TLS Secret created before signing")
			}
			shutdown()
			start() // Restart during a pending manual wait.
			first = pending("")
			upload(first)
			var oldSecret corev1.Secret
			eventually(t, "cert-manager TLS Secret delivery", func() bool {
				err := cl.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &oldSecret)
				return err == nil && len(oldSecret.Data["tls.key"]) > 0 && len(oldSecret.Data["tls.crt"]) > 0
			})
			eventually(t, "durable issued confirmation", func() bool { r, err := db.Get(ctx, first.UID); return err == nil && r.State == "issued" })
			// Trigger the same manual renewal condition as cmctl renew, without
			// changing or deleting the existing TLS Secret.
			if err := cl.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, certificate); err != nil {
				t.Fatal(err)
			}
			apiutil.SetCertificateCondition(certificate, certificate.Generation, cmapi.CertificateConditionIssuing, cmmeta.ConditionTrue, "ManuallyTriggered", "Certificate re-issuance manually triggered")
			if err := cl.Status().Update(ctx, certificate); err != nil {
				t.Fatal(err)
			}
			second := pending(first.UID)
			var during corev1.Secret
			if err := cl.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &during); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(oldSecret.Data["tls.crt"], during.Data["tls.crt"]) || !bytes.Equal(oldSecret.Data["tls.key"], during.Data["tls.key"]) {
				t.Fatal("old TLS Secret changed during manual renewal wait")
			}
			upload(second)
			eventually(t, "renewed Secret replaces certificate and rotates key", func() bool {
				var renewed corev1.Secret
				if err := cl.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &renewed); err != nil {
					return false
				}
				return !bytes.Equal(oldSecret.Data["tls.crt"], renewed.Data["tls.crt"]) && !bytes.Equal(oldSecret.Data["tls.key"], renewed.Data["tls.key"])
			})
			eventually(t, "renewed history confirmation", func() bool { r, err := db.Get(ctx, second.UID); return err == nil && r.State == "issued" })
			if err := client.IgnoreNotFound(cl.Delete(ctx, &cmapi.CertificateRequest{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: first.Name}})); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Access(ctx, first.UID, "operator@example.com", "Historic CSR after Kubernetes deletion"); err != nil {
				t.Fatal(err)
			}
			var count int
			if err := db.Pool.QueryRow(ctx, "SELECT count(*) FROM requests WHERE data::text LIKE '%PRIVATE KEY%' OR snapshot::text LIKE '%PRIVATE KEY%'").Scan(&count); err != nil || count != 0 {
				t.Fatal("private key retained in database", err)
			}
		})
	}
}
