package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
		"recon-example.com-2026-01-31":                "example.com",
		"recon-a-b.example.com-2026-01-31-150405":     "a-b.example.com",
		"recon-example.com-2026-01-31-150405-n1":      "example.com",
		"recon-a-b.example.com-2026-01-31-150405-n12": "a-b.example.com",
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

func startExampleScan(t *testing.T, h http.Handler) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/scans", strings.NewReader(`{"domain":"example.com","profile":"passive","format":"none"}`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestRelativeOutputDirPassedAbsolute(t *testing.T) {
	root := t.TempDir()
	absOut := filepath.Join(root, "out")
	if err := os.Mkdir(absOut, 0o755); err != nil {
		t.Fatal(err)
	}
	probe := filepath.Join(root, "probe.txt")
	script := filepath.Join(root, "fake-recon.sh")
	scriptSrc := `#!/bin/sh
{
  echo "pwd=$(pwd)"
  echo "args=$*"
} > "$PROBE_LOG"
exit 0
`
	if err := os.WriteFile(script, []byte(scriptSrc), 0o755); err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(cwd, absOut)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.IsAbs(rel) {
		t.Skip("cannot construct a relative output path from the test cwd")
	}

	s := &server{
		cfg:     config{OutputDir: rel, MaxConcurrent: 1, ReconScript: script},
		running: map[string]*exec.Cmd{},
	}
	t.Setenv("PROBE_LOG", probe)
	rr := startExampleScan(t, s.routes())
	if rr.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rr.Code, rr.Body.String())
	}
	deadline := time.Now().Add(2 * time.Second)
	var raw []byte
	for time.Now().Before(deadline) {
		raw, err = os.ReadFile(probe)
		if err == nil && len(raw) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("probe log not written: %v", err)
	}
	text := string(raw)
	if !strings.Contains(text, "args=") || !strings.Contains(text, absOut) {
		t.Fatalf("expected absolute --output %q in child args, probe=%q", absOut, text)
	}
	if strings.Contains(text, filepath.Join(absOut, "out")) {
		t.Fatalf("output path was nested: %s", text)
	}
}

func TestScanIDUniqueWhenDirectoryExists(t *testing.T) {
	s, dir := newTestServer(t, "")
	s.cfg.MaxConcurrent = 2
	frozen := time.Date(2026, 11, 26, 15, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return frozen }
	existing := "recon-example.com-2026-11-26-150000"
	if err := os.Mkdir(filepath.Join(dir, existing), 0o755); err != nil {
		t.Fatal(err)
	}
	rr := startExampleScan(t, s.routes())
	if rr.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rr.Code, rr.Body.String())
	}
	var st scanStatus
	if err := json.Unmarshal(rr.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.ID == existing {
		t.Fatalf("reused existing scan id %s", st.ID)
	}
	if st.ID != existing+"-n1" {
		t.Fatalf("got id %s, want %s-n1", st.ID, existing)
	}
	if !scanIDRe.MatchString(st.ID) {
		t.Fatalf("new id %s does not match scanIDRe", st.ID)
	}
}

func TestScanIDUniqueAfterQuickRetry(t *testing.T) {
	s, dir := newTestServer(t, "")
	s.cfg.MaxConcurrent = 2
	frozen := time.Date(2026, 11, 26, 15, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return frozen }

	rr1 := startExampleScan(t, s.routes())
	if rr1.Code != http.StatusAccepted {
		t.Fatalf("first start: expected 202, got %d: %s", rr1.Code, rr1.Body.String())
	}
	var st1 scanStatus
	if err := json.Unmarshal(rr1.Body.Bytes(), &st1); err != nil {
		t.Fatal(err)
	}
	// Simulate a scan that finished in the same second: drop from running, leave the dir
	// (the fake script exits immediately; wait until it is gone from s.running).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		_, still := s.running[st1.ID]
		s.mu.Unlock()
		if !still {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := os.MkdirAll(filepath.Join(dir, st1.ID), 0o755); err != nil {
		t.Fatal(err)
	}

	rr2 := startExampleScan(t, s.routes())
	if rr2.Code != http.StatusAccepted {
		t.Fatalf("retry: expected 202, got %d: %s", rr2.Code, rr2.Body.String())
	}
	var st2 scanStatus
	if err := json.Unmarshal(rr2.Body.Bytes(), &st2); err != nil {
		t.Fatal(err)
	}
	if st2.ID == st1.ID {
		t.Fatalf("retry reused scan id %s", st2.ID)
	}
	if extractDomainFromID(st2.ID) != "example.com" {
		t.Fatalf("domain parse of %s failed", st2.ID)
	}
	_ = dir
}
