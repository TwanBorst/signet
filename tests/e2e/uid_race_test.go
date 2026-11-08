package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/TwanBorst/signet/internal/testutil"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestDeletedRecreatedRequestRejectsOldStatus(t *testing.T) {
	path := os.Getenv("SIGNET_E2E_KUBECONFIG")
	if path == "" {
		t.Skip("disposable cluster required")
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
	ctx := context.Background()
	ns := fmt.Sprintf("signet-race-%d", time.Now().UnixNano())
	if err := cl.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil {
		t.Fatal(err)
	}
	defer cl.Delete(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
	cr, _ := testutil.Request(t, "same-name")
	cr.Namespace = ns
	cr.UID = ""
	cr.CreationTimestamp = metav1.Time{}
	cr.Spec.IssuerRef.Name = "unmanaged-race"
	if err := cl.Create(ctx, cr); err != nil {
		t.Fatal(err)
	}
	cert, _ := testutil.Bundle(t, cr)
	oldPatch, err := json.Marshal(map[string]any{"apiVersion": "cert-manager.io/v1", "kind": "CertificateRequest",
		"metadata": map[string]any{"name": cr.Name, "namespace": cr.Namespace, "uid": cr.UID, "resourceVersion": cr.ResourceVersion},
		"status":   cmapi.CertificateRequestStatus{Certificate: []byte(cert)}})
	if err != nil {
		t.Fatal(err)
	}
	if err := cl.Delete(ctx, cr); err != nil {
		t.Fatal(err)
	}
	replacement, _ := testutil.Request(t, "same-name")
	replacement.Namespace = ns
	replacement.UID = ""
	replacement.CreationTimestamp = metav1.Time{}
	replacement.Spec.IssuerRef.Name = "unmanaged-race"
	if err := cl.Create(ctx, replacement); err != nil {
		t.Fatal(err)
	}
	target := &cmapi.CertificateRequest{ObjectMeta: metav1.ObjectMeta{Name: replacement.Name, Namespace: replacement.Namespace}}
	patchErr := cl.Status().Patch(ctx, target, client.RawPatch(types.ApplyPatchType, oldPatch), client.FieldOwner("signet.io"), client.ForceOwnership)
	if !apierrors.IsConflict(patchErr) && !(apierrors.IsInvalid(patchErr) && strings.Contains(patchErr.Error(), "metadata.uid")) {
		t.Fatalf("expected UID/version conflict, not an unrelated rejection: %v", patchErr)
	}
	if err := cl.Get(ctx, types.NamespacedName{Namespace: ns, Name: replacement.Name}, target); err != nil {
		t.Fatal(err)
	}
	if len(target.Status.Certificate) != 0 {
		t.Fatal("old certificate delivered to new UID")
	}
}
