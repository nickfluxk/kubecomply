// Package dashboard provides an embedded web dashboard for viewing
// KubeComply compliance scan results directly from the agent.
package dashboard

import (
	"embed"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/kubecomply/kubecomply/pkg/scanner"
)

//go:embed static/*
var staticFiles embed.FS

// DashboardData is the JSON payload served to the dashboard frontend.
type DashboardData struct {
	LastUpdated    time.Time          `json:"lastUpdated"`
	ScanResult     *scanner.ScanResult `json:"scanResult,omitempty"`
	ClusterName    string             `json:"clusterName"`
	AgentVersion   string             `json:"agentVersion"`
	UptimeSeconds  float64            `json:"uptimeSeconds"`
}

// Dashboard serves the embedded web UI and exposes a JSON API for
// the latest scan results. It is safe for concurrent use.
type Dashboard struct {
	mu           sync.RWMutex
	latestResult *scanner.ScanResult
	clusterName  string
	agentVersion string
	startTime    time.Time
	logger       *slog.Logger
}

// Option configures a Dashboard instance.
type Option func(*Dashboard)

// WithClusterName sets the cluster name displayed in the dashboard.
func WithClusterName(name string) Option {
	return func(d *Dashboard) {
		d.clusterName = name
	}
}

// WithAgentVersion sets the agent version displayed in the dashboard.
func WithAgentVersion(version string) Option {
	return func(d *Dashboard) {
		d.agentVersion = version
	}
}

// WithLogger sets the structured logger for the dashboard.
func WithLogger(logger *slog.Logger) Option {
	return func(d *Dashboard) {
		d.logger = logger
	}
}

// New creates a new Dashboard with the given options.
func New(opts ...Option) *Dashboard {
	d := &Dashboard{
		startTime:    time.Now(),
		agentVersion: "dev",
		logger:       slog.Default(),
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// UpdateResult stores a new scan result for the dashboard to display.
// This method is goroutine-safe.
func (d *Dashboard) UpdateResult(result *scanner.ScanResult) {
	if result == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.latestResult = result
	d.logger.Info("dashboard scan result updated",
		"scanType", result.ScanType,
		"score", result.Summary.Score,
		"totalChecks", result.Summary.TotalChecks,
	)
}

// Handler returns an http.Handler that serves both the static dashboard
// assets and the JSON API. Mount this on your HTTP mux at the desired path.
//
// Routes:
//
//	GET /dashboard/              — serves the embedded single-page app
//	GET /api/v1/scans/latest     — returns the latest scan result as JSON
//	GET /api/v1/health           — returns a simple health check
func (d *Dashboard) Handler() http.Handler {
	mux := http.NewServeMux()

	// Serve the embedded static files under /dashboard/.
	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		d.logger.Error("failed to create sub filesystem for static assets", "error", err)
		panic("dashboard: failed to load embedded static assets: " + err.Error())
	}
	fileServer := http.FileServer(http.FS(staticFS))
	mux.Handle("/dashboard/", http.StripPrefix("/dashboard/", fileServer))

	// Redirect bare /dashboard to /dashboard/ for convenience.
	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard/", http.StatusMovedPermanently)
	})

	// JSON API: latest scan result.
	mux.HandleFunc("/api/v1/scans/latest", d.handleLatestScan)

	// JSON API: health check.
	mux.HandleFunc("/api/v1/health", d.handleHealth)

	return mux
}

// handleLatestScan serves the most recent scan result as JSON.
func (d *Dashboard) handleLatestScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	d.mu.RLock()
	result := d.latestResult
	d.mu.RUnlock()

	data := DashboardData{
		LastUpdated:   time.Now(),
		ScanResult:    result,
		ClusterName:   d.clusterName,
		AgentVersion:  d.agentVersion,
		UptimeSeconds: time.Since(d.startTime).Seconds(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	if result == nil {
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(data); err != nil {
			d.logger.Error("failed to encode empty dashboard data", "error", err)
		}
		return
	}

	if err := json.NewEncoder(w).Encode(data); err != nil {
		d.logger.Error("failed to encode dashboard data", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}

// handleHealth returns a simple health check response.
func (d *Dashboard) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	d.mu.RLock()
	hasScan := d.latestResult != nil
	d.mu.RUnlock()

	resp := map[string]interface{}{
		"status":        "ok",
		"agentVersion":  d.agentVersion,
		"clusterName":   d.clusterName,
		"uptimeSeconds": time.Since(d.startTime).Seconds(),
		"hasScanResult": hasScan,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		d.logger.Error("failed to encode health response", "error", err)
	}
}
