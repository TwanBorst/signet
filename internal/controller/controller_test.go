package controller_test

import (
	"context"
	"errors"
	"testing"
	"time"

	api "github.com/TwanBorst/signet/api/v1alpha1"
	"github.com/TwanBorst/signet/internal/controller"
	"github.com/TwanBorst/signet/internal/store"
	"github.com/TwanBorst/signet/internal/testutil"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func setup(t *testing.T, cr *cmapi.CertificateRequest) (*controller.Controller, *api.SignetIssuer) {
	t.Helper()
	scheme := runtime.NewScheme()
	cmapi.AddToScheme(scheme)
	api.AddToScheme(scheme)
	i := &api.SignetIssuer{ObjectMeta: metav1.ObjectMeta{Name: "manual", Namespace: "test", UID: "issuer-uid"}}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&cmapi.CertificateRequest{}).WithObjects(cr, i).Build()
	return &controller.Controller{Store: testutil.DB(t), Client: cl, Reader: cl, Instances: []controller.Instance{{Kind: "SignetIssuer", Namespace: "test", Name: "manual"}}}, i
}
func TestApprovalManualIssuanceRestartDeletion(t *testing.T) {
	ctx := context.Background()
	cr, _ := testutil.Request(t, "manual")
	c, i := setup(t, cr)
	key := types.NamespacedName{Namespace: cr.Namespace, Name: cr.Name}
	if _, err := c.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatal(err)
	}
	var approved cmapi.CertificateRequest
	if err := c.Reader.Get(ctx, key, &approved); err != nil {
		t.Fatal(err)
	}
	if !controller.Approved(&approved) {
		t.Fatal("request was not approved")
	}
	obj := signer.CertificateRequestObjectFromCertificateRequest(&approved)
	_, err := c.Sign(ctx, obj, i)
	var wait signer.PendingError
	if !errors.As(err, &wait) {
		t.Fatalf("year-old wait is not PendingError: %v", err)
	}
	cert, ca := testutil.Bundle(t, &approved)
	_, err = c.Store.Mutate(ctx, string(cr.UID), "operator@example.com", "upload", 1, func(r *store.Request) error { r.State = "uploaded"; r.Certificate = cert; r.Chain = ca; return nil })
	if err != nil {
		t.Fatal(err)
	}
	// Recreated controller uses only durable state; private keys are never passed.
	restarted := &controller.Controller{Store: c.Store, Client: c.Client, Reader: c.Reader, Instances: c.Instances}
	bundle, err := restarted.Sign(ctx, obj, i)
	if err != nil || len(bundle.ChainPEM) == 0 {
		t.Fatalf("restart delivery err=%v", err)
	}
	r, err := c.Store.Get(ctx, string(cr.UID))
	if err != nil || r.State != "uploaded" {
		t.Fatal("claimed issuance before Kubernetes confirmation")
	}
	approved.Status.Conditions = append(approved.Status.Conditions, cmapi.CertificateRequestCondition{Type: cmapi.CertificateRequestConditionReady, Status: cmmeta.ConditionTrue, Reason: "Issued", LastTransitionTime: &metav1.Time{Time: time.Now()}})
	if err := c.Client.Status().Update(ctx, &approved); err != nil {
		t.Fatal(err)
	}
	if err := c.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	r, _ = c.Store.Get(ctx, string(cr.UID))
	if r.State != "issued" {
		t.Fatalf("state=%s", r.State)
	}
	if err := c.Client.Delete(ctx, &approved); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Store.Access(ctx, string(cr.UID), "operator@example.com", "Historic download"); err != nil {
		t.Fatal("history lost after deletion", err)
	}
}
func TestScopeDenialAndUnavailableAudit(t *testing.T) {
	ctx := context.Background()
	cr, _ := testutil.Request(t, "scoped")
	c, i := setup(t, cr)
	for _, change := range []func(*cmapi.CertificateRequest){
		func(r *cmapi.CertificateRequest) { r.Spec.IssuerRef.Group = "other" },
		func(r *cmapi.CertificateRequest) { r.Spec.IssuerRef.Kind = "" },
		func(r *cmapi.CertificateRequest) { r.Spec.IssuerRef.Name = "other" },
		func(r *cmapi.CertificateRequest) { r.Namespace = "other" },
	} {
		copy := cr.DeepCopy()
		change(copy)
		if c.Matches(copy) {
			t.Fatal("matched unmanaged issuer")
		}
	}
	cr.Status.Conditions = []cmapi.CertificateRequestCondition{{Type: cmapi.CertificateRequestConditionApproved, Status: cmmeta.ConditionTrue}, {Type: cmapi.CertificateRequestConditionDenied, Status: cmmeta.ConditionTrue}}
	if controller.Approved(cr) {
		t.Fatal("approved a denied request")
	}
	testutil.Ensure(t, c.Store, cr, api.IssuerSpec{}, "issuer-uid")
	_, err := c.Store.Mutate(ctx, string(cr.UID), "operator@example.com", "deny", 1, func(r *store.Request) error { r.State = "denied"; r.Reason = "Unneeded"; return nil })
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Sign(ctx, signer.CertificateRequestObjectFromCertificateRequest(cr), i)
	var permanent signer.PermanentError
	if !errors.As(err, &permanent) {
		t.Fatalf("denial err=%v", err)
	}
	if _, err := c.Store.Pool.Exec(ctx, "ALTER TABLE audit RENAME TO audit_unavailable"); err != nil {
		t.Fatal(err)
	}
	_, err = c.Sign(ctx, signer.CertificateRequestObjectFromCertificateRequest(cr), i)
	var wait signer.PendingError
	if !errors.As(err, &wait) {
		t.Fatalf("audit outage must remain Pending: %v", err)
	}
}
