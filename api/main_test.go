package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDomainValidation(t *testing.T) {
	good := []string{"example.com", "sub.example.com.br", "a-b.example.org"}
	bad := []string{"-h", "--profile", "example", "exa mple.com", "example.com;id", "../etc", ".example.com", "example-.com"}
	for _, d := range good {
		if !domainRe.MatchString(d) {
			t.Errorf("expected valid: %s", d)
		}
	}
	for _, d := range bad {
		if domainRe.MatchString(d) {
			t.Errorf("expected invalid: %s", d)
		}
	}
}

func TestExtractDomainFromID(t *testing.T) {
	cases := map[string]string{
		"recon-example.com-2026-01-31":            "example.com",
		"recon-a-b.example.com-2026-01-31-150405": "a-b.example.com",
	}
	for id, want := range cases {
		if got := extractDomainFromID(id); got != want {
			t.Errorf("%s: got %s want %s", id, got, want)
		}
	}
}

func newTestServer(t *testing.T, token string) (*server, string) {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-recon.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return &server{cfg: config{OutputDir: dir, Token: token, MaxConcurrent: 1, ReconScript: script},
		running: map[string]*exec.Cmd{}}, dir
}

func TestAuthAndValidation(t *testing.T) {
	s, dir := newTestServer(t, "s3cret")
	h := s.routes()

	req := httptest.NewRequest(http.MethodGet, "/api/scans", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", rr.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/scans", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 with token, got %d", rr.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/scans", strings.NewReader(`{"domain":"-h"}`))
	req.Header.Set("Authorization", "Bearer s3cret")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for argument-like domain, got %d", rr.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/scans", strings.NewReader(`{"domain":"example.com","profile":"passive","report_lang":"en"}`))
	req.Header.Set("Authorization", "Bearer s3cret")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rr.Code, rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/scans/..%2f..%2fetc", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest && rr.Code != http.StatusNotFound {
		t.Fatalf("expected 400/404 for traversal, got %d", rr.Code)
	}
	_ = dir
}
