package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

const defaultPort = "8080"
const defaultOutputDir = "/app/output"
const reconScript = "/app/recon.sh"

var scanIDRe = regexp.MustCompile(`^recon-[a-zA-Z0-9][a-zA-Z0-9.-]*-[0-9]{4}-[0-9]{2}-[0-9]{2}$`)

type config struct {
	Port      string
	OutputDir string
}

type scanRequest struct {
	Domain string `json:"domain"`
}

type scanStatus struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	StartedAt string `json:"started_at,omitempty"`
	FinishedAt string `json:"finished_at,omitempty"`
}

type statusFile struct {
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
	Status     string `json:"status"`
	Error      string `json:"error,omitempty"`
}

type report struct {
	ID          string   `json:"id"`
	Domain      string   `json:"domain"`
	Status      string   `json:"status"`
	StartedAt   string   `json:"started_at"`
	FinishedAt  string   `json:"finished_at"`
	Error       string   `json:"error,omitempty"`
	Subdomains  []string `json:"subdomains"`
	Hosts       hosts   `json:"hosts"`
	URLs        []string `json:"urls"`
	JS          js      `json:"js"`
	Vulns       []any    `json:"vulns"`
	Nikto       []any    `json:"nikto,omitempty"`
	ZAP         []any    `json:"zap,omitempty"`
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
	cfg := config{
		Port:      getEnv("PORT", defaultPort),
		OutputDir: getEnv("OUTPUT_DIR", defaultOutputDir),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/scans", handleScans(cfg))
	mux.HandleFunc("/api/scans/", handleScanByID(cfg))
	addr := ":" + cfg.Port
	fmt.Printf("API server listening on %s (output dir: %s)\n", addr, cfg.OutputDir)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(1)
	}
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func handleScans(cfg config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/scans" {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
			dirs, err := os.ReadDir(cfg.OutputDir)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			var ids []string
			for _, d := range dirs {
				if d.IsDir() && strings.HasPrefix(d.Name(), "recon-") && scanIDRe.MatchString(d.Name()) {
					ids = append(ids, d.Name())
				}
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string][]string{"scans": ids})
		case http.MethodPost:
			handlePostScans(cfg)(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func handleScanByID(cfg config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/scans/")
		if id == "" || !scanIDRe.MatchString(id) {
			http.Error(w, "invalid scan id", http.StatusBadRequest)
			return
		}
		scanDir := filepath.Join(cfg.OutputDir, id)
		switch r.Method {
		case http.MethodGet:
			info, err := os.Stat(scanDir)
			if err != nil || !info.IsDir() {
				http.NotFound(w, r)
				return
			}
			statusPath := filepath.Join(scanDir, "status.json")
			statusData, err := os.ReadFile(statusPath)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(scanStatus{ID: id, Status: "running"})
				return
			}
			var sf statusFile
			if err := json.Unmarshal(statusData, &sf); err != nil {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(scanStatus{ID: id, Status: "running"})
				return
			}
			if sf.Status != "completed" && sf.FinishedAt == "" {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(scanStatus{
					ID:        id,
					Status:    "running",
					StartedAt: sf.StartedAt,
				})
				return
			}
			rep, err := buildReport(cfg, id, scanDir, sf)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(rep)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func buildReport(cfg config, id, scanDir string, sf statusFile) (*report, error) {
	domain := extractDomainFromID(id)
	rep := &report{
		ID:         id,
		Domain:     domain,
		Status:     sf.Status,
		StartedAt:  sf.StartedAt,
		FinishedAt: sf.FinishedAt,
		Error:      sf.Error,
		Subdomains: readLines(filepath.Join(scanDir, "subdomains.txt")),
		Hosts: hosts{
			Resolved: readLines(filepath.Join(scanDir, "hosts", "resolved.txt")),
			Ports:    readLines(filepath.Join(scanDir, "hosts", "ports.txt")),
			Alive:    readLines(filepath.Join(scanDir, "hosts", "alive.txt")),
		},
		URLs: readLines(filepath.Join(scanDir, "urls.txt")),
		JS: js{
			Endpoints: readLines(filepath.Join(scanDir, "js", "endpoints.txt")),
			URLs:      readLines(filepath.Join(scanDir, "js", "js_urls.txt")),
		},
		Vulns: readNucleiJSON(filepath.Join(scanDir, "vulns", "nuclei.json")),
		Nikto: readNiktoReports(scanDir),
		ZAP:   readZAPReports(scanDir),
	}
	return rep, nil
}

func extractDomainFromID(id string) string {
	// id = recon-example.com-2025-02-25 -> example.com
	s := strings.TrimPrefix(id, "recon-")
	if idx := strings.LastIndex(s, "-"); idx != -1 {
		return s[:idx]
	}
	return s
}

func readLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func readNucleiJSON(path string) []any {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []any
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var v map[string]any
		if err := json.Unmarshal(sc.Bytes(), &v); err != nil {
			continue
		}
		out = append(out, v)
	}
	return out
}

func readNiktoReports(scanDir string) []any {
	vulnsDir := filepath.Join(scanDir, "vulns")
	entries, err := os.ReadDir(vulnsDir)
	if err != nil {
		return nil
	}
	var out []any
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "nikto_") || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(vulnsDir, e.Name()))
		if err != nil {
			continue
		}
		var v any
		if json.Unmarshal(data, &v) != nil {
			continue
		}
		out = append(out, v)
	}
	return out
}

func readZAPReports(scanDir string) []any {
	vulnsDir := filepath.Join(scanDir, "vulns")
	entries, err := os.ReadDir(vulnsDir)
	if err != nil {
		return nil
	}
	var out []any
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "zap_") || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(vulnsDir, e.Name()))
		if err != nil {
			continue
		}
		var v any
		if json.Unmarshal(data, &v) != nil {
			continue
		}
		out = append(out, v)
	}
	return out
}

func handlePostScans(cfg config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/scans" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var req scanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		domain := strings.TrimSpace(req.Domain)
		if domain == "" {
			http.Error(w, "domain is required", http.StatusBadRequest)
			return
		}
		if !isValidDomain(domain) {
			http.Error(w, "invalid domain", http.StatusBadRequest)
			return
		}
		scanID := fmt.Sprintf("recon-%s-%s", domain, dateToday())
		scanDir := filepath.Join(cfg.OutputDir, scanID)
		if _, err := os.Stat(scanDir); err == nil {
			http.Error(w, "scan already exists for this domain today", http.StatusConflict)
			return
		}
		cmd := exec.Command(reconScript, "-d", domain)
		cmd.Dir = cfg.OutputDir
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		go func() { _ = cmd.Wait() }()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(scanStatus{ID: scanID, Status: "running"})
	}
}

func dateToday() string {
	// Use same format as recon.sh: date +%F -> YYYY-MM-DD
	out, err := exec.Command("date", "+%Y-%m-%d").Output()
	if err != nil {
		return "0000-00-00"
	}
	return strings.TrimSpace(string(out))
}

func isValidDomain(s string) bool {
	if len(s) > 253 || len(s) < 2 {
		return false
	}
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' {
			continue
		}
		return false
	}
	return true
}
