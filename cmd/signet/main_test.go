package main

import (
	"slices"
	"testing"
)

func TestPublicOrigins(t *testing.T) {
	for _, tc := range []struct {
		name, single, multiple string
		want                   []string
	}{
		{"legacy", "https://signet.example.com", "", []string{"https://signet.example.com"}},
		{"multiple", "", `["https://signet.example.com","https://signet.example.org:8443"]`, []string{"https://signet.example.com", "https://signet.example.org:8443"}},
		{"missing", "", "", nil},
		{"both", "https://signet.example.com", `["https://signet.example.org"]`, nil},
		{"empty", "", `[]`, nil},
		{"null", "", `null`, nil},
		{"not JSON", "", "https://signet.example.com", nil},
		{"wrong type", "", `["https://signet.example.com",1]`, nil},
		{"duplicate", "", `["https://signet.example.com","https://signet.example.com"]`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := publicOrigins(tc.single, tc.multiple)
			if tc.want == nil {
				if err == nil {
					t.Fatal("invalid configuration accepted")
				}
			} else if err != nil || !slices.Equal(got, tc.want) {
				t.Fatalf("got %v, %v; want %v", got, err, tc.want)
			}
		})
	}
	for _, origin := range []string{"http://signet.example.com", "https://*.example.com", "https://signet.example.com/", "https://user@signet.example.com", "https://signet.example.com?", "https://signet.example.com#", "https://signet.example.com:0", "https://signet.example.com:65536", " https://signet.example.com", "https://signet.example.com,https://signet.example.org"} {
		t.Run(origin, func(t *testing.T) {
			if _, err := publicOrigins(origin, ""); err == nil {
				t.Fatal("unsafe origin accepted")
			}
		})
	}
}
