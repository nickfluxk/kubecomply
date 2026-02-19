package report

import (
	"fmt"
	"html/template"
	"io"
	"sort"
	"time"

	"github.com/kubecomply/kubecomply/pkg/scanner"
)

// HTMLReporter generates a self-contained HTML compliance report with embedded CSS.
type HTMLReporter struct{}

// htmlData holds the template data for HTML report generation.
type htmlData struct {
	Title        string
	GeneratedAt  string
	ScanType     string
	ClusterName  string
	Duration     string
	Score        float64
	ScoreClass   string
	TotalChecks  int
	PassedChecks int
	FailedChecks int
	Findings     []htmlFinding
	Critical     int
	High         int
	Medium       int
	Low          int
	Info         int
}

type htmlFinding struct {
	ID            string
	Title         string
	Description   string
	Severity      string
	SeverityClass string
	Status        string
	StatusClass   string
	Category      string
	Resource      string
	Namespace     string
	Remediation   string
}

// Generate writes a self-contained HTML report.
func (r *HTMLReporter) Generate(w io.Writer, result *scanner.ScanResult) error {
	data := buildHTMLData(result)

	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("parsing HTML template: %w", err)
	}

	if err := tmpl.Execute(w, data); err != nil {
		return fmt.Errorf("executing HTML template: %w", err)
	}

	return nil
}

func buildHTMLData(result *scanner.ScanResult) htmlData {
	data := htmlData{
		Title:        "KubeComply Compliance Report",
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
		ScanType:     result.ScanType,
		ClusterName:  result.ClusterName,
		Duration:     result.Duration.Round(time.Millisecond).String(),
		Score:        result.Summary.Score,
		TotalChecks:  result.Summary.TotalChecks,
		PassedChecks: result.Summary.PassedChecks,
		FailedChecks: result.Summary.FailedChecks,
		Critical:     result.Summary.FindingsBySeverity[scanner.SeverityCritical],
		High:         result.Summary.FindingsBySeverity[scanner.SeverityHigh],
		Medium:       result.Summary.FindingsBySeverity[scanner.SeverityMedium],
		Low:          result.Summary.FindingsBySeverity[scanner.SeverityLow],
		Info:         result.Summary.FindingsBySeverity[scanner.SeverityInfo],
	}

	if data.Score >= 90 {
		data.ScoreClass = "score-excellent"
	} else if data.Score >= 70 {
		data.ScoreClass = "score-good"
	} else if data.Score >= 50 {
		data.ScoreClass = "score-fair"
	} else {
		data.ScoreClass = "score-poor"
	}

	// Sort findings: failures first, then by severity.
	sorted := make([]scanner.Finding, len(result.Findings))
	copy(sorted, result.Findings)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Status != sorted[j].Status {
			if sorted[i].Status == scanner.StatusFail {
				return true
			}
			if sorted[j].Status == scanner.StatusFail {
				return false
			}
		}
		return scanner.SeverityRank(sorted[i].Severity) > scanner.SeverityRank(sorted[j].Severity)
	})

	for _, f := range sorted {
		hf := htmlFinding{
			ID:          f.ID,
			Title:       f.Title,
			Description: f.Description,
			Severity:    string(f.Severity),
			Status:      string(f.Status),
			Category:    f.Category,
			Resource:    f.Resource,
			Namespace:   f.Namespace,
			Remediation: f.Remediation,
		}

		switch f.Severity {
		case scanner.SeverityCritical:
			hf.SeverityClass = "sev-critical"
		case scanner.SeverityHigh:
			hf.SeverityClass = "sev-high"
		case scanner.SeverityMedium:
			hf.SeverityClass = "sev-medium"
		case scanner.SeverityLow:
			hf.SeverityClass = "sev-low"
		default:
			hf.SeverityClass = "sev-info"
		}

		switch f.Status {
		case scanner.StatusPass:
			hf.StatusClass = "status-pass"
		case scanner.StatusFail:
			hf.StatusClass = "status-fail"
		case scanner.StatusWarning:
			hf.StatusClass = "status-warning"
		default:
			hf.StatusClass = "status-other"
		}

		data.Findings = append(data.Findings, hf)
	}

	return data
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{.Title}}</title>
<style>
  :root {
    --bg: #0f172a; --surface: #1e293b; --border: #334155;
    --text: #e2e8f0; --text-muted: #94a3b8;
    --critical: #ef4444; --high: #f97316; --medium: #eab308; --low: #3b82f6; --info: #6b7280;
    --pass: #22c55e; --fail: #ef4444; --warning: #eab308;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; }
  .container { max-width: 1200px; margin: 0 auto; }
  h1 { font-size: 1.8rem; margin-bottom: 0.5rem; }
  .meta { color: var(--text-muted); font-size: 0.875rem; margin-bottom: 2rem; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; }
  .card-label { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); }
  .card-value { font-size: 2rem; font-weight: 700; margin-top: 0.25rem; }
  .score-excellent { color: var(--pass); }
  .score-good { color: #22d3ee; }
  .score-fair { color: var(--warning); }
  .score-poor { color: var(--fail); }
  .severity-bar { display: flex; gap: 0.75rem; margin-bottom: 2rem; flex-wrap: wrap; }
  .sev-badge { padding: 0.35rem 0.75rem; border-radius: 4px; font-size: 0.8rem; font-weight: 600; }
  .sev-critical { background: rgba(239,68,68,0.15); color: var(--critical); border: 1px solid var(--critical); }
  .sev-high { background: rgba(249,115,22,0.15); color: var(--high); border: 1px solid var(--high); }
  .sev-medium { background: rgba(234,179,8,0.15); color: var(--medium); border: 1px solid var(--medium); }
  .sev-low { background: rgba(59,130,246,0.15); color: var(--low); border: 1px solid var(--low); }
  .sev-info { background: rgba(107,114,128,0.15); color: var(--info); border: 1px solid var(--info); }
  table { width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 8px; overflow: hidden; }
  th { background: #0f172a; padding: 0.75rem 1rem; text-align: left; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); border-bottom: 1px solid var(--border); }
  td { padding: 0.75rem 1rem; border-bottom: 1px solid var(--border); font-size: 0.875rem; vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  .status-pass { color: var(--pass); font-weight: 600; }
  .status-fail { color: var(--fail); font-weight: 600; }
  .status-warning { color: var(--warning); font-weight: 600; }
  .status-other { color: var(--text-muted); }
  .remediation { color: var(--text-muted); font-size: 0.8rem; margin-top: 0.35rem; font-style: italic; }
  footer { margin-top: 2rem; text-align: center; color: var(--text-muted); font-size: 0.75rem; }
</style>
</head>
<body>
<div class="container">
  <h1>{{.Title}}</h1>
  <div class="meta">
    Cluster: <strong>{{.ClusterName}}</strong> |
    Scan Type: <strong>{{.ScanType}}</strong> |
    Duration: {{.Duration}} |
    Generated: {{.GeneratedAt}}
  </div>

  <div class="cards">
    <div class="card">
      <div class="card-label">Compliance Score</div>
      <div class="card-value {{.ScoreClass}}">{{printf "%.1f" .Score}}%</div>
    </div>
    <div class="card">
      <div class="card-label">Total Checks</div>
      <div class="card-value">{{.TotalChecks}}</div>
    </div>
    <div class="card">
      <div class="card-label">Passed</div>
      <div class="card-value score-excellent">{{.PassedChecks}}</div>
    </div>
    <div class="card">
      <div class="card-label">Failed</div>
      <div class="card-value score-poor">{{.FailedChecks}}</div>
    </div>
  </div>

  <div class="severity-bar">
    <span class="sev-badge sev-critical">Critical: {{.Critical}}</span>
    <span class="sev-badge sev-high">High: {{.High}}</span>
    <span class="sev-badge sev-medium">Medium: {{.Medium}}</span>
    <span class="sev-badge sev-low">Low: {{.Low}}</span>
    <span class="sev-badge sev-info">Info: {{.Info}}</span>
  </div>

  <table>
    <thead>
      <tr>
        <th>ID</th>
        <th>Status</th>
        <th>Severity</th>
        <th>Title</th>
        <th>Category</th>
        <th>Resource</th>
      </tr>
    </thead>
    <tbody>
      {{range .Findings}}
      <tr>
        <td>{{.ID}}</td>
        <td><span class="{{.StatusClass}}">{{.Status}}</span></td>
        <td><span class="sev-badge {{.SeverityClass}}">{{.Severity}}</span></td>
        <td>
          {{.Title}}
          {{if .Remediation}}<div class="remediation">{{.Remediation}}</div>{{end}}
        </td>
        <td>{{.Category}}</td>
        <td>{{if .Namespace}}{{.Namespace}}/{{end}}{{.Resource}}</td>
      </tr>
      {{end}}
    </tbody>
  </table>

  <footer>
    Generated by KubeComply &mdash; Kubernetes Compliance Scanner
  </footer>
</div>
</body>
</html>
`
