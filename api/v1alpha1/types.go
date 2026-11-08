// Copyright 2023 The cert-manager Authors.
// Copyright 2026 Signet contributors.
// SPDX-License-Identifier: Apache-2.0
// Adapted from cert-manager/sample-external-issuer's issuer API.
package v1alpha1

import (
	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var GroupVersion = schema.GroupVersion{Group: "signet.io", Version: "v1alpha1"}

type IssuerSpec struct {
	CABundle string   `json:"caBundle,omitempty"`
	DNSNames []string `json:"dnsNames,omitempty"`
}

type SignetIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              IssuerSpec             `json:"spec,omitempty"`
	Status            issuerapi.IssuerStatus `json:"status,omitempty"`
}

type SignetClusterIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              IssuerSpec             `json:"spec,omitempty"`
	Status            issuerapi.IssuerStatus `json:"status,omitempty"`
}

type SignetIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SignetIssuer `json:"items"`
}

type SignetClusterIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SignetClusterIssuer `json:"items"`
}

func (i *SignetIssuer) GetConditions() []metav1.Condition        { return i.Status.Conditions }
func (i *SignetClusterIssuer) GetConditions() []metav1.Condition { return i.Status.Conditions }
func (*SignetIssuer) GetIssuerTypeIdentifier() string            { return "signetissuers.signet.io" }
func (*SignetClusterIssuer) GetIssuerTypeIdentifier() string     { return "signetclusterissuers.signet.io" }

func (i *SignetIssuer) DeepCopyObject() runtime.Object {
	o := *i
	o.ObjectMeta = *i.ObjectMeta.DeepCopy()
	o.Spec.DNSNames = append([]string(nil), i.Spec.DNSNames...)
	o.Status.Conditions = append([]metav1.Condition(nil), i.Status.Conditions...)
	return &o
}
func (i *SignetClusterIssuer) DeepCopyObject() runtime.Object {
	o := *i
	o.ObjectMeta = *i.ObjectMeta.DeepCopy()
	o.Spec.DNSNames = append([]string(nil), i.Spec.DNSNames...)
	o.Status.Conditions = append([]metav1.Condition(nil), i.Status.Conditions...)
	return &o
}
func (i *SignetIssuerList) DeepCopyObject() runtime.Object {
	o := *i
	o.ListMeta = *i.ListMeta.DeepCopy()
	o.Items = make([]SignetIssuer, len(i.Items))
	for n := range i.Items {
		o.Items[n] = *i.Items[n].DeepCopyObject().(*SignetIssuer)
	}
	return &o
}
func (i *SignetClusterIssuerList) DeepCopyObject() runtime.Object {
	o := *i
	o.ListMeta = *i.ListMeta.DeepCopy()
	o.Items = make([]SignetClusterIssuer, len(i.Items))
	for n := range i.Items {
		o.Items[n] = *i.Items[n].DeepCopyObject().(*SignetClusterIssuer)
	}
	return &o
}
func AddToScheme(s *runtime.Scheme) error {
	s.AddKnownTypes(GroupVersion, &SignetIssuer{}, &SignetIssuerList{}, &SignetClusterIssuer{}, &SignetClusterIssuerList{})
	metav1.AddToGroupVersion(s, GroupVersion)
	return nil
}
