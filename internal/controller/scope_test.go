package controller_test

import (
	"context"
	"errors"
	"testing"

	"github.com/TwanBorst/signet/internal/controller"
	"github.com/TwanBorst/signet/internal/store"
	"github.com/TwanBorst/signet/internal/testutil"
)

func TestDeploymentScope(t *testing.T) {
	for _, scope := range []controller.Scope{
		{Mode: "cluster"},
		{Mode: "namespace", Namespace: "team-a"},
	} {
		t.Run(scope.Mode, func(t *testing.T) {
			if err := scope.Validate(); err != nil {
				t.Fatal(err)
			}
			c := &controller.Controller{Scope: scope}
			for _, kind := range []string{"SignetIssuer", "SignetClusterIssuer", "Issuer", ""} {
				for _, namespace := range []string{"team-a", "team-b"} {
					for _, name := range []string{"first", "newly-created"} {
						cr, _ := testutil.Request(t, "scope")
						cr.Namespace = namespace
						cr.Spec.IssuerRef.Kind, cr.Spec.IssuerRef.Name = kind, name
						want := (kind == "SignetIssuer" || kind == "SignetClusterIssuer") &&
							(scope.Mode == "cluster" || (kind == "SignetIssuer" && namespace == scope.Namespace))
						if c.Matches(cr) != want {
							t.Fatalf("kind=%s namespace=%s name=%s: want %v", kind, namespace, name, want)
						}
						cr.Spec.IssuerRef.Group = "other.io"
						if c.Matches(cr) {
							t.Fatal("matched another API group")
						}
						cr.Spec.IssuerRef.Group = "signet.io"
						cr.Spec.IssuerRef.Name = ""
						if c.Matches(cr) {
							t.Fatal("matched an empty issuer name")
						}
					}
				}
			}
			namespaces := scope.CacheOptions().DefaultNamespaces
			if scope.Mode == "cluster" && len(namespaces) != 0 {
				t.Fatal("cluster cache is restricted")
			}
			if scope.Mode == "namespace" {
				if _, ok := namespaces["team-a"]; !ok || len(namespaces) != 1 {
					t.Fatal("namespace cache must watch only team-a")
				}
			}
		})
	}
	for _, scope := range []controller.Scope{
		{}, {Mode: "invalid"}, {Mode: "cluster", Namespace: "team-a"},
		{Mode: "namespace"}, {Mode: "namespace", Namespace: "Team_A"},
	} {
		if err := scope.Validate(); err == nil {
			t.Fatalf("accepted invalid scope %+v", scope)
		}
	}
}

func TestNamespaceLiveRejectsOutOfScopeBeforeKubernetes(t *testing.T) {
	c := &controller.Controller{Scope: controller.Scope{Mode: "namespace", Namespace: "team-a"}}
	for _, request := range []store.Request{
		{Namespace: "team-b", IssuerKind: "SignetIssuer"},
		{Namespace: "team-a", IssuerKind: "SignetClusterIssuer"},
	} {
		var rejected *store.ActionError
		if err := c.Live(context.Background(), request); !errors.As(err, &rejected) || rejected.Status != 409 {
			t.Fatalf("expected scope rejection, got %v", err)
		}
	}
}
