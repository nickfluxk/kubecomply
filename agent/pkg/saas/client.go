// Package saas provides the client for KubeComply Professional SaaS integration.
// It handles license validation, scan result uploads, and drift event reporting.
// All operations gracefully degrade when the SaaS endpoint is unreachable.
package saas

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/kubecomply/kubecomply/pkg/scanner"
)

const (
	// DefaultEndpoint is the default SaaS API base URL.
	DefaultEndpoint = "https://api.kubecomply.io"

	// defaultTimeout is the HTTP client timeout.
	defaultTimeout = 30 * time.Second

	// apiVersion is the API version prefix.
	apiVersion = "/api/v1"
)

// Client communicates with the KubeComply Professional SaaS platform.
type Client struct {
	endpoint   string
	httpClient *http.Client
	token      string
	clusterID  string
	logger     *slog.Logger
}

// LicenseResponse is returned by the license validation endpoint.
type LicenseResponse struct {
	Valid     bool     `json:"valid"`
	Token     string   `json:"token"`
	ClusterID string   `json:"clusterId"`
	Features  []string `json:"features"`
	ExpiresAt string   `json:"expiresAt,omitempty"`
	Message   string   `json:"message,omitempty"`
}

// UploadResponse is returned after uploading scan results.
type UploadResponse struct {
	ScanID  string `json:"scanId"`
	URL     string `json:"url,omitempty"`
	Message string `json:"message,omitempty"`
}

// DriftEvent represents a configuration drift event.
type DriftEvent struct {
	ID           string    `json:"id"`
	ResourceKind string    `json:"resourceKind"`
	ResourceName string    `json:"resourceName"`
	Namespace    string    `json:"namespace,omitempty"`
	ChangeType   string    `json:"changeType"` // "created", "modified", "deleted"
	Field        string    `json:"field,omitempty"`
	OldValue     string    `json:"oldValue,omitempty"`
	NewValue     string    `json:"newValue,omitempty"`
	Timestamp    time.Time `json:"timestamp"`
}

// NewClient creates a new SaaS client.
func NewClient(endpoint string, logger *slog.Logger) *Client {
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	if logger == nil {
		logger = slog.Default()
	}

	return &Client{
		endpoint: endpoint,
		httpClient: &http.Client{
			Timeout: defaultTimeout,
		},
		logger: logger,
	}
}

// ValidateLicense validates a license key against the SaaS platform and
// returns an authentication token, cluster ID, and available features.
func (c *Client) ValidateLicense(ctx context.Context, licenseKey string) (*LicenseResponse, error) {
	body := map[string]string{
		"licenseKey": licenseKey,
	}

	resp, err := c.doRequest(ctx, http.MethodPost, "/licenses/validate", body, "")
	if err != nil {
		return nil, fmt.Errorf("license validation request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleErrorResponse(resp, "license validation")
	}

	var result LicenseResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding license response: %w", err)
	}

	if !result.Valid {
		return &result, fmt.Errorf("license is not valid: %s", result.Message)
	}

	c.token = result.Token
	c.clusterID = result.ClusterID
	c.logger.Info("license validated", "clusterID", result.ClusterID, "features", result.Features)

	return &result, nil
}

// UploadScanResults uploads completed scan results to the SaaS platform.
// Returns nil error if the SaaS endpoint is unreachable (offline mode).
func (c *Client) UploadScanResults(ctx context.Context, token string, result *scanner.ScanResult) (*UploadResponse, error) {
	if token == "" {
		token = c.token
	}
	if token == "" {
		c.logger.Warn("no SaaS token available, skipping scan upload")
		return nil, nil
	}

	resp, err := c.doRequest(ctx, http.MethodPost, "/scans", result, token)
	if err != nil {
		// Gracefully handle offline mode.
		c.logger.Warn("SaaS unreachable, continuing in offline mode", "error", err)
		return nil, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, c.handleErrorResponse(resp, "scan upload")
	}

	var uploadResp UploadResponse
	if err := json.NewDecoder(resp.Body).Decode(&uploadResp); err != nil {
		return nil, fmt.Errorf("decoding upload response: %w", err)
	}

	c.logger.Info("scan results uploaded", "scanID", uploadResp.ScanID, "url", uploadResp.URL)
	return &uploadResp, nil
}

// SendDriftEvents sends configuration drift events to the SaaS platform.
// Returns nil error if the SaaS endpoint is unreachable (offline mode).
func (c *Client) SendDriftEvents(ctx context.Context, token string, events []DriftEvent) error {
	if token == "" {
		token = c.token
	}
	if token == "" {
		c.logger.Warn("no SaaS token available, skipping drift event upload")
		return nil
	}

	if len(events) == 0 {
		return nil
	}

	body := map[string]interface{}{
		"clusterID": c.clusterID,
		"events":    events,
	}

	resp, err := c.doRequest(ctx, http.MethodPost, "/drift/events", body, token)
	if err != nil {
		c.logger.Warn("SaaS unreachable for drift events, continuing in offline mode", "error", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return c.handleErrorResponse(resp, "drift events upload")
	}

	c.logger.Info("drift events uploaded", "count", len(events))
	return nil
}

// Token returns the current authentication token.
func (c *Client) Token() string {
	return c.token
}

// ClusterID returns the cluster ID from license validation.
func (c *Client) ClusterID() string {
	return c.clusterID
}

// IsAuthenticated returns true if the client has a valid token.
func (c *Client) IsAuthenticated() bool {
	return c.token != ""
}

// doRequest performs an HTTP request to the SaaS API.
func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}, token string) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		jsonBytes, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshaling request body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBytes)
	}

	url := c.endpoint + apiVersion + path
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "kubecomply-agent/1.0")

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	return c.httpClient.Do(req)
}

// handleErrorResponse extracts error details from a non-success HTTP response.
func (c *Client) handleErrorResponse(resp *http.Response, operation string) error {
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	var errorBody struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(bodyBytes, &errorBody); err == nil && errorBody.Message != "" {
		return fmt.Errorf("%s failed (HTTP %d): %s", operation, resp.StatusCode, errorBody.Message)
	}

	return fmt.Errorf("%s failed (HTTP %d): %s", operation, resp.StatusCode, string(bodyBytes))
}
