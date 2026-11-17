package e2e

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	api "github.com/TwanBorst/signet/api/v1alpha1"
	"github.com/TwanBorst/signet/internal/controller"
	"github.com/TwanBorst/signet/internal/store"
	"github.com/TwanBorst/signet/internal/testutil"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

func TestNamespaceDeploymentWithRestrictedRBAC(t *testing.T) {
	path := os.Getenv("SIGNET_E2E_KUBECONFIG")
	if path == "" {
		t.Skip("SIGNET_E2E_KUBECONFIG not set; disposable cert-manager cluster required")
	}
	raw, err := clientcmd.LoadFromFile(path)
	if err != nil || !strings.HasPrefix(raw.CurrentContext, "kind-signet-") {
		t.Fatal("refusing non-Signet disposable cluster")
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", path)
	if err != nil {
		t.Fatal(err)
	}
	scheme := runtime.NewScheme()
	cmapi.AddToScheme(scheme)
	api.AddToScheme(scheme)
	corev1.AddToScheme(scheme)
	rbacv1.AddToScheme(scheme)
	admin, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ns := fmt.Sprintf("signet-scope-%d", time.Now().UnixNano())
	if err := admin.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Delete(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}) })
	objects := []client.Object{
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "signet", Namespace: ns}},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "signet", Namespace: ns}, Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{"signet.io"}, Resources: []string{"signetissuers"}, Verbs: []string{"get", "list", "watch"}},
			{APIGroups: []string{"signet.io"}, Resources: []string{"signetissuers/status"}, Verbs: []string{"get", "patch", "update"}},
			{APIGroups: []string{"cert-manager.io"}, Resources: []string{"certificaterequests"}, Verbs: []string{"get", "list", "watch"}},
			{APIGroups: []string{"cert-manager.io"}, Resources: []string{"certificaterequests/status"}, Verbs: []string{"get", "patch", "update"}},
			{APIGroups: []string{"cert-manager.io"}, Resources: []string{"certificaterequests/approval"}, Verbs: []string{"update"}},
			{APIGroups: []string{"events.k8s.io"}, Resources: []string{"events"}, Verbs: []string{"create", "patch"}},
		}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "signet", Namespace: ns},
			RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "signet"},
			Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: ns, Name: "signet"}}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: ns}, Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{"cert-manager.io"}, Resources: []string{"signers"}, Verbs: []string{"approve"}, ResourceNames: []string{"signetissuers.signet.io/*"}},
		}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: ns},
			RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: ns},
			Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: ns, Name: "signet"}}},
	}
	for _, obj := range objects {
		if err := admin.Create(ctx, obj); err != nil {
			t.Fatal(err)
		}
		if obj.GetNamespace() == "" {
			t.Cleanup(func() { admin.Delete(ctx, obj) })
		}
	}
	restricted := rest.CopyConfig(cfg)
	restricted.Impersonate = rest.ImpersonationConfig{UserName: "system:serviceaccount:" + ns + ":signet"}
	cl, err := client.New(restricted, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	eventually(t, "namespace role propagation", func() bool {
		return cl.List(ctx, &api.SignetIssuerList{}, client.InNamespace(ns)) == nil
	})
	for _, err := range []error{
		cl.List(ctx, &api.SignetIssuerList{}),
		cl.List(ctx, &api.SignetClusterIssuerList{}),
		cl.List(ctx, &cmapi.CertificateRequestList{}, client.InNamespace("default")),
		cl.Get(ctx, types.NamespacedName{Namespace: ns, Name: "unreadable"}, &corev1.Secret{}),
	} {
		if !apierrors.IsForbidden(err) {
			t.Fatalf("expected forbidden access outside namespace role, got %v", err)
		}
	}
	scope := controller.Scope{Mode: "namespace", Namespace: ns}
	mgr, err := ctrl.NewManager(restricted, ctrl.Options{Scheme: scheme, Cache: scope.CacheOptions(),
		Metrics: server.Options{BindAddress: "0"}, Controller: config.Controller{SkipNameValidation: new(true)}})
	if err != nil {
		t.Fatal(err)
	}
	db := testutil.DB(t)
	c := &controller.Controller{Scope: scope, Store: db}
	runctx, cancel := context.WithCancel(ctx)
	if err := c.Setup(runctx, mgr); err != nil {
		cancel()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- mgr.Start(runctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(20 * time.Second):
			t.Error("namespace manager did not shut down")
		}
	})
	// New issuers must be discovered without reconfiguring or restarting Signet.
	for _, name := range []string{"first", "created-later"} {
		issuer := &api.SignetIssuer{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}}
		if err := admin.Create(ctx, issuer); err != nil {
			t.Fatal(err)
		}
		cr, _ := testutil.Request(t, name)
		cr.Namespace, cr.UID, cr.CreationTimestamp = ns, "", metav1.Time{}
		cr.Spec.IssuerRef.Name = name
		if err := admin.Create(ctx, cr); err != nil {
			t.Fatal(err)
		}
		key := types.NamespacedName{Namespace: ns, Name: name}
		eventually(t, "namespace issuer readiness and request approval", func() bool {
			if admin.Get(ctx, key, issuer) != nil || !meta.IsStatusConditionTrue(issuer.Status.Conditions, "Ready") {
				return false
			}
			var live cmapi.CertificateRequest
			if admin.Get(ctx, key, &live) != nil || !controller.Approved(&live) {
				return false
			}
			r, err := db.Get(ctx, string(live.UID))
			return err == nil && r.State == "pending"
		})
	}
	cr, _ := testutil.Request(t, "cluster-ignored")
	cr.Namespace, cr.UID, cr.CreationTimestamp = ns, "", metav1.Time{}
	cr.Spec.IssuerRef.Kind = "SignetClusterIssuer"
	if err := admin.Create(ctx, cr); err != nil {
		t.Fatal(err)
	}
	// Recovery must also skip historical records that are no longer in scope.
	testutil.Ensure(t, db, cr, api.IssuerSpec{}, "old-issuer")
	remote, _ := testutil.Request(t, "remote-history")
	remote.Namespace = "default"
	testutil.Ensure(t, db, remote, api.IssuerSpec{}, "old-issuer")
	if err := c.Sweep(ctx); err != nil {
		t.Fatalf("recovery attempted out-of-scope access: %v", err)
	}
	var live cmapi.CertificateRequest
	if err := admin.Get(ctx, types.NamespacedName{Namespace: ns, Name: cr.Name}, &live); err != nil {
		t.Fatal(err)
	}
	if controller.Approved(&live) {
		t.Fatal("namespace deployment approved a cluster issuer request")
	}
	if err := c.Live(ctx, store.Request{Namespace: "default", IssuerKind: "SignetIssuer"}); err == nil {
		t.Fatal("namespace deployment accepted an out-of-scope action")
	} else {
		var rejection *store.ActionError
		if !errors.As(err, &rejection) {
			t.Fatal(err)
		}
	}
}
