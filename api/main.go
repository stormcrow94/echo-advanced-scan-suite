// ECHO Advanced Scan Suite - REST API (stdlib only).
//
// Environment:
//
//	ECHO_API_ADDR        listen address (default ":" + PORT, PORT default 8080)
//	ECHO_API_TOKEN       when set, every /api request needs "Authorization: Bearer <token>"
//	ECHO_MAX_CONCURRENT  max scans running at once (default 2)
//	OUTPUT_DIR           scan output root (default /app/output)
//	ECHO_RECON_SCRIPT    path to recon.sh (default /app/recon.sh)
package main

import (
	"bufio"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	scanIDRe = regexp.MustCompile(`^recon-[a-z0-9][a-z0-9.-]*-[0-9]{4}-[0-9]{2}-[0-9]{2}(-[0-9]{6})?$`)
	domainRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	nameRe   = regexp.MustCompile(`^[\p{L}\p{N} .,&()_'/-]{0,80}$`)
)

type config struct {
	Addr          string
	OutputDir     string
	Token         string
	MaxConcurrent int
	ReconScript   string
}

type server struct {
	cfg     config
	mu      sync.Mutex
	running map[string]*exec.Cmd
}

type scanRequest struct {
	Domain     string `json:"domain"`
	Profile    string `json:"profile,omitempty"`     // passive | standard | deep
	ReportLang string `json:"report_lang,omitempty"` // en | pt-BR | both
	Format     string `json:"format,omitempty"`      // pdf | json | both | none
	Title      string `json:"title,omitempty"`
	Client     string `json:"client,omitempty"`
	Author     string `json:"author,omitempty"`
}

type scanStatus struct {
	ID         string `json:"id"`
	Status     string `json:"status"`
	StartedAt  string `json:"started_at,omitempty"`
	FinishedAt string `json:"finished_at,omitempty"`
}

type statusFile struct {
	ID         string           `json:"id"`
	Domain     string           `json:"domain"`
	Profile    string           `json:"profile"`
	StartedAt  string           `json:"started_at"`
	FinishedAt string           `json:"finished_at"`
	Status     string           `json:"status"`
	Error      string           `json:"error,omitempty"`
	Modules    []map[string]any `json:"modules,omitempty"`
}

type report struct {
	ID          string           `json:"id"`
	Domain      string           `json:"domain"`
	Profile     string           `json:"profile,omitempty"`
	Status      string           `json:"status"`
	StartedAt   string           `json:"started_at"`
	FinishedAt  string           `json:"finished_at"`
	Error       string           `json:"error,omitempty"`
	Modules     []map[string]any `json:"modules,omitempty"`
	Subdomains  []string         `json:"subdomains"`
	Hosts       hosts            `json:"hosts"`
	URLs        []string         `json:"urls"`
	JS          js               `json:"js"`
	Vulns       []any            `json:"vulns"`
	Nikto       []any            `json:"nikto,omitempty"`
	ZAP         []any            `json:"zap,omitempty"`
	ReportFiles []string         `json:"report_files,omitempty"`
}

type hosts struct {
	Resolved []string `json:"resolved"`
	Ports    []string `json:"ports"`
	Alive    []string `json:"alive"`
}

type js struct {
	Endpoints []string `json:"endpoints"`
	URLs      []string `json:"urls,omitempty"`
}

func main() {
	port := getEnv("PORT", "8080")
	maxc, err := strconv.Atoi(getEnv("ECHO_MAX_CONCURRENT", "2"))
	if err != nil || maxc < 1 {
		maxc = 2
	}
	cfg := config{
		Addr:          getEnv("ECHO_API_ADDR", ":"+port),
		OutputDir:     getEnv("OUTPUT_DIR", getEnv("ECHO_OUTPUT_DIR", "/app/output")),
		Token:         os.Getenv("ECHO_API_TOKEN"),
		MaxConcurrent: maxc,
		ReconScript:   getEnv("ECHO_RECON_SCRIPT", "/app/recon.sh"),
	}
	if err := os.MkdirAll(cfg.OutputDir, 0o755); err != nil {
		log.Fatalf("output dir: %v", err)
	}
	s := &server{cfg: cfg, running: map[string]*exec.Cmd{}}
	if cfg.Token == "" {
		log.Printf("WARNING: ECHO_API_TOKEN is not set - the API is UNAUTHENTICATED. Anyone who can reach %s can start scans.", cfg.Addr)
	}
	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("ECHO API listening on %s (output dir: %s, max concurrent scans: %d)", cfg.Addr, cfg.OutputDir, cfg.MaxConcurrent)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("listen: %v", err)
	}
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "running": s.runningCount()})
	})
	mux.HandleFunc("GET /api/scans", s.auth(s.listScans))
	mux.HandleFunc("POST /api/scans", s.auth(s.startScan))
	mux.HandleFunc("GET /api/scans/{id}", s.auth(s.getScan))
	mux.HandleFunc("GET /api/scans/{id}/report", s.auth(s.getReportFile))
	return mux
}

func (s *server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.Token != "" {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.Token)) != 1 {
				writeErr(w, http.StatusUnauthorized, "unauthorized")
				return
			}
		}
		next(w, r)
	}
}

func (s *server) runningCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.running)
}

func (s *server) listScans(w http.ResponseWriter, _ *http.Request) {
	dirs, err := os.ReadDir(s.cfg.OutputDir)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	ids := []string{}
	for _, d := range dirs {
		if d.IsDir() && scanIDRe.MatchString(d.Name()) {
			ids = append(ids, d.Name())
		}
	}
	sort.Strings(ids)
	writeJSON(w, http.StatusOK, map[string][]string{"scans": ids})
}

func (s *server) startScan(w http.ResponseWriter, r *http.Request) {
	var req scanRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	domain := strings.ToLower(strings.TrimSpace(req.Domain))
	if domain == "" {
		writeErr(w, http.StatusBadRequest, "domain is required")
		return
	}
	if len(domain) > 253 || !domainRe.MatchString(domain) {
		writeErr(w, http.StatusBadRequest, "invalid domain")
		return
	}
	args := []string{"-d", domain, "--no-banner"}
	if v, ok := oneOf(req.Profile, "passive", "standard", "deep"); !ok {
		writeErr(w, http.StatusBadRequest, "invalid profile (passive|standard|deep)")
		return
	} else if v != "" {
		args = append(args, "--profile", v)
	}
	if v, ok := oneOf(req.ReportLang, "en", "pt-BR", "both"); !ok {
		writeErr(w, http.StatusBadRequest, "invalid report_lang (en|pt-BR|both)")
		return
	} else if v != "" {
		args = append(args, "--report-lang", v)
	}
	if v, ok := oneOf(req.Format, "pdf", "json", "both", "none"); !ok {
		writeErr(w, http.StatusBadRequest, "invalid format (pdf|json|both|none)")
		return
	} else if v != "" {
		args = append(args, "--format", v)
	}
	for flag, val := range map[string]string{"--report-title": req.Title, "--client": req.Client, "--author": req.Author} {
		if val == "" {
			continue
		}
		if !nameRe.MatchString(val) || strings.HasPrefix(val, "-") {
			writeErr(w, http.StatusBadRequest, "invalid "+strings.TrimPrefix(flag, "--"))
			return
		}
		args = append(args, flag, val)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.running) >= s.cfg.MaxConcurrent {
		writeErr(w, http.StatusTooManyRequests, "too many scans running")
		return
	}
	for id := range s.running {
		if strings.HasPrefix(id, "recon-"+domain+"-") {
			writeErr(w, http.StatusConflict, "a scan for this domain is already running: "+id)
			return
		}
	}
	scanID := fmt.Sprintf("recon-%s-%s", domain, time.Now().Format("2006-01-02-150405"))
	args = append(args, "--scan-id", scanID, "--output", s.cfg.OutputDir)
	cmd := exec.Command(s.cfg.ReconScript, args...)
	cmd.Dir = s.cfg.OutputDir
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.running[scanID] = cmd
	go func() {
		_ = cmd.Wait()
		s.mu.Lock()
		delete(s.running, scanID)
		s.mu.Unlock()
	}()
	writeJSON(w, http.StatusAccepted, scanStatus{ID: scanID, Status: "running"})
}

func (s *server) scanDir(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	id := r.PathValue("id")
	if !scanIDRe.MatchString(id) {
		writeErr(w, http.StatusBadRequest, "invalid scan id")
		return "", "", false
	}
	dir := filepath.Join(s.cfg.OutputDir, id)
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		writeErr(w, http.StatusNotFound, "scan not found")
		return "", "", false
	}
	return id, dir, true
}

func (s *server) getScan(w http.ResponseWriter, r *http.Request) {
	id, dir, ok := s.scanDir(w, r)
	if !ok {
		return
	}
	var sf statusFile
	data, err := os.ReadFile(filepath.Join(dir, "status.json"))
	if err != nil || json.Unmarshal(data, &sf) != nil {
		writeJSON(w, http.StatusOK, scanStatus{ID: id, Status: "running"})
		return
	}
	if sf.Status == "running" {
		writeJSON(w, http.StatusOK, map[string]any{"id": id, "status": "running", "started_at": sf.StartedAt, "modules": sf.Modules})
		return
	}
	writeJSON(w, http.StatusOK, buildReport(id, dir, sf))
}

// GET /api/scans/{id}/report?format=pdf|json&lang=en|pt-BR
func (s *server) getReportFile(w http.ResponseWriter, r *http.Request) {
	_, dir, ok := s.scanDir(w, r)
	if !ok {
		return
	}
	format, okf := oneOf(r.URL.Query().Get("format"), "pdf", "json")
	lang, okl := oneOf(r.URL.Query().Get("lang"), "en", "pt-BR")
	if !okf || !okl {
		writeErr(w, http.StatusBadRequest, "format must be pdf|json and lang en|pt-BR")
		return
	}
	if format == "" {
		format = "pdf"
	}
	if lang == "" {
		lang = "pt-BR"
	}
	path := filepath.Join(dir, "report", "report-"+lang+"."+format)
	if _, err := os.Stat(path); err != nil {
		writeErr(w, http.StatusNotFound, "report not found (scan still running or generated with another lang/format)")
		return
	}
	if format == "pdf" {
		w.Header().Set("Content-Type", "application/pdf")
	} else {
		w.Header().Set("Content-Type", "application/json")
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filepath.Base(dir)+"-"+lang+"."+format))
	http.ServeFile(w, r, path)
}

func buildReport(id, dir string, sf statusFile) *report {
	domain := sf.Domain
	if domain == "" {
		domain = extractDomainFromID(id)
	}
	rep := &report{
		ID: id, Domain: domain, Profile: sf.Profile, Status: sf.Status,
		StartedAt: sf.StartedAt, FinishedAt: sf.FinishedAt, Error: sf.Error, Modules: sf.Modules,
		Subdomains: readLines(filepath.Join(dir, "subdomains.txt")),
		Hosts: hosts{
			Resolved: readLines(filepath.Join(dir, "hosts", "resolved.txt")),
			Ports:    readLines(filepath.Join(dir, "hosts", "ports.txt")),
			Alive:    readLines(filepath.Join(dir, "hosts", "alive.txt")),
		},
		URLs: readLines(filepath.Join(dir, "urls.txt")),
		JS: js{
			Endpoints: readLines(filepath.Join(dir, "js", "endpoints.txt")),
			URLs:      readLines(filepath.Join(dir, "js", "js_urls.txt")),
		},
		Vulns: readJSONL(filepath.Join(dir, "vulns", "nuclei.json")),
		Nikto: readJSONFiles(filepath.Join(dir, "vulns"), "nikto_"),
		ZAP:   readJSONFiles(filepath.Join(dir, "vulns"), "zap_"),
	}
	if entries, err := os.ReadDir(filepath.Join(dir, "report")); err == nil {
		for _, e := range entries {
			rep.ReportFiles = append(rep.ReportFiles, e.Name())
		}
	}
	return rep
}

// recon-example.com-2026-01-31[-150405] -> example.com
func extractDomainFromID(id string) string {
	s := strings.TrimPrefix(id, "recon-")
	re := regexp.MustCompile(`-[0-9]{4}-[0-9]{2}-[0-9]{2}(-[0-9]{6})?$`)
	return re.ReplaceAllString(s, "")
}

func readLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			out = append(out, line)
		}
	}
	return out
}

func readJSONL(path string) []any {
	var out []any
	for _, line := range readLines(path) {
		var v map[string]any
		if json.Unmarshal([]byte(line), &v) == nil {
			out = append(out, v)
		}
	}
	return out
}

func readJSONFiles(dir, prefix string) []any {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []any
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), prefix) || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var v any
		if json.Unmarshal(data, &v) == nil {
			out = append(out, v)
		}
	}
	return out
}

func oneOf(v string, allowed ...string) (string, bool) {
	if v == "" {
		return "", true
	}
	for _, a := range allowed {
		if v == a {
			return v, true
		}
	}
	return v, false
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
