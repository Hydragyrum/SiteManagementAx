package main

import (
	"net"
	"net/url"
	"testing"
)

func TestValidateExternalHostRejectsLocalhost(t *testing.T) {
	if err := validateExternalHost("localhost"); err == nil {
		t.Fatalf("expected localhost to be rejected")
	}
}

func TestIsDisallowedIP(t *testing.T) {
	cases := []struct {
		ip         string
		disallowed bool
	}{
		{ip: "127.0.0.1", disallowed: true},
		{ip: "10.1.2.3", disallowed: true},
		{ip: "192.168.1.12", disallowed: true},
		{ip: "172.16.4.5", disallowed: true},
		{ip: "169.254.10.11", disallowed: true},
		{ip: "8.8.8.8", disallowed: false},
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		if got := isDisallowedIP(ip); got != tc.disallowed {
			t.Fatalf("ip %s disallowed=%v, expected %v", tc.ip, got, tc.disallowed)
		}
	}
}

func TestHostPortURI(t *testing.T) {
	parsed, err := url.Parse("https://example.com/a/b?x=1")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	host, port, uri, ssl := hostPortURI(parsed)
	if host != "example.com" || port != 443 || uri != "/a/b?x=1" || !ssl {
		t.Fatalf("unexpected parse result: host=%s port=%d uri=%s ssl=%v", host, port, uri, ssl)
	}

	parsed, err = url.Parse("http://example.com:8080")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	host, port, uri, ssl = hostPortURI(parsed)
	if host != "example.com" || port != 8080 || uri != "/" || ssl {
		t.Fatalf("unexpected explicit-port result: host=%s port=%d uri=%s ssl=%v", host, port, uri, ssl)
	}
}

func TestHeaderParsingHelpers(t *testing.T) {
	if got := fileNameFromHeader(`attachment; filename="payload.exe"`); got != "payload.exe" {
		t.Fatalf("unexpected filename: %q", got)
	}
	if got := fileNameFromHeader(""); got != "" {
		t.Fatalf("expected empty filename, got %q", got)
	}

	if got := contentTypeFromHeader("text/html; charset=utf-8"); got != "text/html" {
		t.Fatalf("unexpected content type: %q", got)
	}
	if got := contentTypeFromHeader(""); got != "application/octet-stream" {
		t.Fatalf("unexpected default content type: %q", got)
	}
}
