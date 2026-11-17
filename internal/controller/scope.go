package controller

import (
	"errors"

	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/cache"
)

type Scope struct {
	Mode      string
	Namespace string
}

func (s Scope) Validate() error {
	switch s.Mode {
	case "cluster":
		if s.Namespace != "" {
			return errors.New("cluster deployment must not specify a namespace")
		}
	case "namespace":
		if s.Namespace == "" || len(validation.IsDNS1123Label(s.Namespace)) != 0 {
			return errors.New("namespace deployment requires a valid namespace")
		}
	default:
		return errors.New("deployment mode must be cluster or namespace")
	}
	return nil
}

func (s Scope) Manages(kind, namespace string) bool {
	switch s.Mode {
	case "cluster":
		return kind == "SignetIssuer" || kind == "SignetClusterIssuer"
	case "namespace":
		return s.Namespace != "" && kind == "SignetIssuer" && namespace == s.Namespace
	default:
		return false
	}
}

func (s Scope) CacheOptions() cache.Options {
	if s.Mode == "namespace" {
		return cache.Options{DefaultNamespaces: map[string]cache.Config{s.Namespace: {}}}
	}
	return cache.Options{}
}
