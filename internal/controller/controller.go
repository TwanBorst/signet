// Copyright 2023 The cert-manager Authors.
// Copyright 2026 Signet contributors.
// SPDX-License-Identifier: Apache-2.0
// Controller wiring is adapted from sample-external-issuer.
package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	api "github.com/TwanBorst/signet/api/v1alpha1"
	"github.com/TwanBorst/signet/internal/pki"
	"github.com/TwanBorst/signet/internal/store"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/controllers"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type Instance struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}
type Controller struct {
	Client    client.Client
	Reader    client.Reader
	Store     *store.Store
	Instances []Instance
}

func (c *Controller) Matches(cr *cmapi.CertificateRequest) bool {
	if cr.Spec.IssuerRef.Group != api.GroupVersion.Group {
		return false
	}
	ns := cr.Namespace
	if cr.Spec.IssuerRef.Kind == "SignetClusterIssuer" {
		ns = ""
	}
	for _, i := range c.Instances {
		if i.Kind == cr.Spec.IssuerRef.Kind && i.Name == cr.Spec.IssuerRef.Name && i.Namespace == ns {
			return true
		}
	}
	return false
}
func condition(cr *cmapi.CertificateRequest, kind cmapi.CertificateRequestConditionType) bool {
	for _, v := range cr.Status.Conditions {
		if v.Type == kind && v.Status == cmmeta.ConditionTrue {
			return true
		}
	}
	return false
}
func Approved(cr *cmapi.CertificateRequest) bool {
	return condition(cr, cmapi.CertificateRequestConditionApproved) && !condition(cr, cmapi.CertificateRequestConditionDenied)
}
func terminal(cr *cmapi.CertificateRequest) string {
	if condition(cr, cmapi.CertificateRequestConditionDenied) {
		return "denied"
	}
	if condition(cr, cmapi.CertificateRequestConditionReady) {
		return "issued"
	}
	if cr.Status.FailureTime != nil {
		return "failed"
	}
	for _, v := range cr.Status.Conditions {
		if v.Type == cmapi.CertificateRequestConditionReady && v.Status == cmmeta.ConditionFalse && v.Reason == cmapi.CertificateRequestReasonFailed {
			return "failed"
		}
	}
	return ""
}
func policy(i issuerapi.Issuer) (api.IssuerSpec, error) {
	switch i := i.(type) {
	case *api.SignetIssuer:
		return i.Spec, nil
	case *api.SignetClusterIssuer:
		return i.Spec, nil
	default:
		return api.IssuerSpec{}, errors.New("unsupported issuer kind")
	}
}
func (c *Controller) Issuer(ctx context.Context, cr *cmapi.CertificateRequest) (issuerapi.Issuer, error) {
	var i issuerapi.Issuer
	ns := cr.Namespace
	switch cr.Spec.IssuerRef.Kind {
	case "SignetIssuer":
		i = &api.SignetIssuer{}
	case "SignetClusterIssuer":
		i = &api.SignetClusterIssuer{}
		ns = ""
	default:
		return nil, errors.New("unsupported issuer reference")
	}
	if err := c.Reader.Get(ctx, types.NamespacedName{Namespace: ns, Name: cr.Spec.IssuerRef.Name}, i.(client.Object)); err != nil {
		return nil, err
	}
	return i, nil
}

func (c *Controller) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var cr cmapi.CertificateRequest
	if err := c.Reader.Get(ctx, req.NamespacedName, &cr); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !c.Matches(&cr) {
		return ctrl.Result{}, nil
	}
	if cr.DeletionTimestamp != nil {
		return ctrl.Result{}, nil
	}
	if state := terminal(&cr); state != "" {
		_, err := c.Store.Get(ctx, string(cr.UID))
		var ae *store.ActionError
		if errors.As(err, &ae) && ae.Status == 404 {
			return ctrl.Result{}, nil
		}
		if err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, c.Store.Transition(ctx, string(cr.UID), state, "Observed Kubernetes request outcome")
	}
	if Approved(&cr) {
		if _, err := c.Store.Get(ctx, string(cr.UID)); err == nil {
			return ctrl.Result{}, nil
		} else {
			var ae *store.ActionError
			if !errors.As(err, &ae) || ae.Status != 404 {
				return ctrl.Result{}, err
			}
		}
	}
	i, err := c.Issuer(ctx, &cr)
	if err != nil {
		return ctrl.Result{}, err
	}
	spec, err := policy(i)
	if err != nil {
		return ctrl.Result{}, err
	}
	if err := c.Store.Record(ctx, string(cr.UID), "system:controller", "csr.access", "success", "Approval policy evaluation"); err != nil {
		return ctrl.Result{}, err
	}
	template, validationErr := pki.Template(&cr, spec)
	if validationErr != nil {
		if err := c.Store.Record(ctx, string(cr.UID), "system:approver", "approval", "failure", validationErr.Error()); err != nil {
			return ctrl.Result{}, err
		}
		if err := c.Store.Ensure(ctx, store.Request{UID: string(cr.UID), Name: cr.Name, Namespace: cr.Namespace,
			IssuerKind: cr.Spec.IssuerRef.Kind, IssuerName: cr.Spec.IssuerRef.Name, State: "failed", Reason: validationErr.Error()},
			store.Snapshot{Request: cmapi.CertificateRequest{ObjectMeta: metav1.ObjectMeta{UID: cr.UID, Name: cr.Name, Namespace: cr.Namespace}}, IssuerUID: string(i.GetUID())}); err != nil {
			return ctrl.Result{}, err
		}
		if !Approved(&cr) {
			return ctrl.Result{}, c.setApproval(ctx, &cr, false, "Request violates issuer safety policy")
		}
		return ctrl.Result{}, nil // Sign records the permanent validation failure.
	}
	snapshot := cr.DeepCopy()
	snapshot.ObjectMeta = metav1.ObjectMeta{Name: cr.Name, Namespace: cr.Namespace, UID: cr.UID, CreationTimestamp: cr.CreationTimestamp}
	snapshot.Spec.Username = ""
	snapshot.Spec.Groups = nil
	snapshot.Spec.Extra = nil
	details, err := signer.CertificateRequestObjectFromCertificateRequest(&cr).GetCertificateDetails()
	if err != nil {
		return ctrl.Result{}, err
	}
	if err := c.Store.Ensure(ctx, store.Request{UID: string(cr.UID), Namespace: cr.Namespace, Name: cr.Name,
		IssuerKind: cr.Spec.IssuerRef.Kind, IssuerName: cr.Spec.IssuerRef.Name, DNSNames: template.DNSNames,
		Usages: cr.Spec.Usages, Duration: details.Duration.String(), IsCA: cr.Spec.IsCA, Requester: cr.Spec.Username},
		store.Snapshot{Request: *snapshot, Policy: spec, IssuerUID: string(i.GetUID())}); err != nil {
		return ctrl.Result{}, err
	}
	if !Approved(&cr) {
		if err := c.setApproval(ctx, &cr, true, "Validated against configured Signet issuer policy"); err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}
func (c *Controller) setApproval(ctx context.Context, cr *cmapi.CertificateRequest, approve bool, reason string) error {
	if condition(cr, cmapi.CertificateRequestConditionApproved) || condition(cr, cmapi.CertificateRequestConditionDenied) {
		return nil
	}
	if err := c.Store.Record(ctx, string(cr.UID), "system:approver", "approval.intent", "success", reason); err != nil {
		return err
	}
	base := cr.DeepCopy()
	kind := cmapi.CertificateRequestConditionDenied
	if approve {
		kind = cmapi.CertificateRequestConditionApproved
	}
	now := metav1.Now()
	cr.Status.Conditions = append(cr.Status.Conditions, cmapi.CertificateRequestCondition{
		Type: kind, Status: cmmeta.ConditionTrue, Reason: "SignetPolicy", Message: reason, LastTransitionTime: &now,
	})
	err := c.Client.Status().Patch(ctx, cr, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{}))
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	if aerr := c.Store.Record(ctx, string(cr.UID), "system:approver", "approval."+string(kind), outcome, "Kubernetes status patch attempt"); aerr != nil {
		return aerr
	}
	return err
}

func (c *Controller) Check(ctx context.Context, i issuerapi.Issuer) error {
	p, err := policy(i)
	if err != nil {
		return signer.PermanentError{Err: err}
	}
	if err = pki.ValidatePolicy(p); err != nil {
		return signer.PermanentError{Err: err}
	}
	return c.Store.Pool.Ping(ctx)
}
func pending(reason string) (signer.PEMBundle, error) {
	return signer.PEMBundle{}, signer.PendingError{Err: errors.New(reason), RequeueAfter: 15 * time.Second}
}

func (c *Controller) Sign(ctx context.Context, obj signer.CertificateRequestObject, i issuerapi.Issuer) (signer.PEMBundle, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	uid := string(obj.GetUID())
	// A DB outage remains Pending, not a finite retry error, even after a
	// months-long manual wait. No certificate is returned without durable audit.
	r, err := c.Store.Get(ctx, uid)
	if err != nil {
		return pending("durable request state unavailable")
	}
	if r.State == "pending" {
		return pending("waiting for operator certificate upload")
	}
	if r.State == "denied" || r.State == "cancelled" || r.State == "failed" || r.State == "deleted" {
		if err := c.Store.Record(ctx, uid, "system:controller", "issuance.stop", "success", r.State); err != nil {
			return pending("durable audit unavailable")
		}
		return signer.PEMBundle{}, signer.PermanentError{Err: fmt.Errorf("operator outcome: %s; %s", r.State, r.Reason)}
	}
	var cr cmapi.CertificateRequest
	if err := c.Reader.Get(ctx, types.NamespacedName{Namespace: r.Namespace, Name: r.Name}, &cr); err != nil {
		return pending("Kubernetes request unavailable")
	}
	if string(cr.UID) != uid || !c.Matches(&cr) || !Approved(&cr) || cr.DeletionTimestamp != nil {
		return pending("request no longer eligible")
	}
	snap, err := c.Store.Access(ctx, uid, "system:controller", "Certificate delivery validation")
	if err != nil {
		return pending("durable audit unavailable")
	}
	current, err := policy(i)
	if err != nil {
		return pending("issuer policy unavailable")
	}
	a, _ := json.Marshal(current)
	b, _ := json.Marshal(snap.Policy)
	if string(i.GetUID()) != snap.IssuerUID || string(a) != string(b) || store.Fingerprint(&cr) != store.Fingerprint(&snap.Request) {
		return c.fail(ctx, uid, "request or issuer policy changed; create a new CertificateRequest")
	}
	if _, err := pki.Validate(&snap.Request, snap.Policy, r.Certificate, r.Chain, time.Now()); err != nil {
		return c.fail(ctx, uid, err.Error())
	}
	// Intent is committed before issuer-lib patches Kubernetes. A separate
	// observer confirms issuance; crashes between systems never report success.
	if err := c.Store.Record(ctx, uid, "system:controller", "issuance.intent", "success", "Validated bundle ready for Kubernetes status patch"); err != nil {
		return pending("durable audit unavailable")
	}
	return signer.PEMBundle{ChainPEM: []byte(r.Certificate + "\n" + r.Chain)}, nil
}
func (c *Controller) fail(ctx context.Context, uid, reason string) (signer.PEMBundle, error) {
	if err := c.Store.Transition(ctx, uid, "failed", reason); err != nil {
		return pending("durable audit unavailable")
	}
	return signer.PEMBundle{}, signer.PermanentError{Err: errors.New(reason)}
}

func (c *Controller) Live(ctx context.Context, r store.Request) error {
	var cr cmapi.CertificateRequest
	if err := c.Reader.Get(ctx, types.NamespacedName{Namespace: r.Namespace, Name: r.Name}, &cr); err != nil {
		return store.Reject(409, "Kubernetes request is unavailable")
	}
	if string(cr.UID) != r.UID || !c.Matches(&cr) || !Approved(&cr) || cr.DeletionTimestamp != nil || terminal(&cr) != "" {
		return store.Reject(409, "request is deleted, terminal, unapproved, or no longer managed")
	}
	return nil
}
func (c *Controller) Sweep(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	requests, err := c.Store.Active(ctx)
	if err != nil {
		return err
	}
	for _, r := range requests {
		var cr cmapi.CertificateRequest
		err := c.Reader.Get(ctx, types.NamespacedName{Namespace: r.Namespace, Name: r.Name}, &cr)
		if apierrors.IsNotFound(err) || (err == nil && (string(cr.UID) != r.UID || cr.DeletionTimestamp != nil)) {
			if err := c.Store.Transition(ctx, r.UID, "deleted", "Kubernetes request deleted; history retained"); err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else if state := terminal(&cr); state != "" {
			if err := c.Store.Transition(ctx, r.UID, state, "Observed Kubernetes request outcome"); err != nil {
				return err
			}
		}
	}
	return nil
}

type sweeper struct{ c *Controller }

func (s sweeper) Start(ctx context.Context) error {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		if err := s.c.Sweep(ctx); err != nil {
			log.FromContext(ctx).Error(errors.New("recovery sweep failed"), "durable store or Kubernetes unavailable")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}
func (s sweeper) NeedLeaderElection() bool { return false }
func (c *Controller) Setup(ctx context.Context, mgr ctrl.Manager) error {
	c.Client = mgr.GetClient()
	c.Reader = mgr.GetAPIReader()
	if err := ctrl.NewControllerManagedBy(mgr).Named("signet-approver-observer").For(&cmapi.CertificateRequest{}).Complete(c); err != nil {
		return err
	}
	if err := mgr.Add(sweeper{c}); err != nil {
		return err
	}
	return (&controllers.CombinedController{
		IssuerTypes: []issuerapi.Issuer{&api.SignetIssuer{}}, ClusterIssuerTypes: []issuerapi.Issuer{&api.SignetClusterIssuer{}},
		FieldOwner: "signet.io", MaxRetryDuration: time.Minute, DisableKubernetesCSRController: true,
		Sign: c.Sign, Check: c.Check, EventRecorder: mgr.GetEventRecorder("signet.io"),
		IgnoreIssuer: func(_ context.Context, i issuerapi.Issuer) (bool, error) {
			kind := "SignetIssuer"
			if _, ok := i.(*api.SignetClusterIssuer); ok {
				kind = "SignetClusterIssuer"
			}
			for _, inst := range c.Instances {
				if inst.Kind == kind && inst.Name == i.GetName() && inst.Namespace == i.GetNamespace() {
					return false, nil
				}
			}
			return true, nil
		},
		IgnoreCertificateRequest: func(ctx context.Context, r signer.CertificateRequestObject, gvk schema.GroupVersionKind, name types.NamespacedName) (bool, error) {
			for _, inst := range c.Instances {
				if inst.Kind == gvk.Kind && inst.Name == name.Name && inst.Namespace == name.Namespace {
					var live cmapi.CertificateRequest
					if err := c.Reader.Get(ctx, types.NamespacedName{Namespace: r.GetNamespace(), Name: r.GetName()}, &live); err != nil {
						return true, err
					}
					if !c.Matches(&live) || !Approved(&live) || live.UID != r.GetUID() {
						return true, nil
					}
					if _, err := c.Store.Get(ctx, string(r.GetUID())); err != nil {
						return true, err
					}
					if err := c.Store.Record(ctx, string(r.GetUID()), "system:controller", "reconcile.intent", "success", "Eligible approved request status reconciliation"); err != nil {
						return true, err
					}
					return false, nil
				}
			}
			return true, nil
		},
	}).SetupWithManager(ctx, mgr)
}
