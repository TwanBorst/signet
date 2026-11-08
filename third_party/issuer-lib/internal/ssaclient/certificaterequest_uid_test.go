package ssaclient

import (
	"encoding/json"
	"testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

func TestCertificateRequestPatchBindsUIDAndVersion(t *testing.T) {
	obj, patch, err := GenerateCertificateRequestStatusPatch("request", "test", "immutable-uid", "42", &cmapi.CertificateRequestStatus{})
	if err != nil {
		t.Fatal(err)
	}
	data, err := patch.Data(&obj)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Metadata struct {
			UID     string `json:"uid"`
			Version string `json:"resourceVersion"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Metadata.UID != "immutable-uid" || decoded.Metadata.Version != "42" {
		t.Fatal("patch lacks immutable identity/version preconditions")
	}
}
