// Package metrics provides Prometheus metrics for the KubeComply agent.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/kubecomply/kubecomply/pkg/scanner"
)

const (
	namespace = "kubecomply"
)

var (
	// ScanDuration tracks the time taken for compliance scans.
	ScanDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "scan_duration_seconds",
			Help:      "Duration of compliance scans in seconds.",
			Buckets:   prometheus.ExponentialBuckets(1, 2, 10), // 1s to ~512s
		},
		[]string{"scan_type", "status"},
	)

	// ComplianceScore is the latest compliance score as a percentage.
	ComplianceScore = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "compliance_score",
			Help:      "Latest compliance score as a percentage (0-100).",
		},
		[]string{"scan_type", "cluster"},
	)

	// FindingsTotal counts the total number of findings by severity.
	FindingsTotal = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "findings_total",
			Help:      "Total number of findings by severity from the latest scan.",
		},
		[]string{"severity", "scan_type", "cluster"},
	)

	// ScanTotal counts the total number of scans executed.
	ScanTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "scan_total",
			Help:      "Total number of compliance scans executed.",
		},
		[]string{"scan_type", "status"},
	)

	// LastScanTimestamp records the Unix timestamp of the last scan.
	LastScanTimestamp = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "last_scan_timestamp",
			Help:      "Unix timestamp of the last compliance scan.",
		},
		[]string{"scan_type", "cluster"},
	)

	// ChecksEvaluated tracks the number of checks in the latest scan.
	ChecksEvaluated = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "checks_evaluated_total",
			Help:      "Total number of checks evaluated in the latest scan.",
		},
		[]string{"scan_type", "cluster"},
	)
)

// RecordScanResult updates all metrics from a completed scan result.
func RecordScanResult(result *scanner.ScanResult, cluster string, scanStatus string) {
	scanType := result.ScanType

	// Record scan duration.
	ScanDuration.WithLabelValues(scanType, scanStatus).Observe(result.Duration.Seconds())

	// Record compliance score.
	ComplianceScore.WithLabelValues(scanType, cluster).Set(result.Summary.Score)

	// Record findings by severity. Reset all severities first to avoid stale data.
	for _, sev := range []scanner.Severity{
		scanner.SeverityCritical,
		scanner.SeverityHigh,
		scanner.SeverityMedium,
		scanner.SeverityLow,
		scanner.SeverityInfo,
	} {
		count := float64(result.Summary.FindingsBySeverity[sev])
		FindingsTotal.WithLabelValues(string(sev), scanType, cluster).Set(count)
	}

	// Record scan total.
	ScanTotal.WithLabelValues(scanType, scanStatus).Inc()

	// Record last scan timestamp.
	LastScanTimestamp.WithLabelValues(scanType, cluster).Set(float64(result.EndTime.Unix()))

	// Record total checks evaluated.
	ChecksEvaluated.WithLabelValues(scanType, cluster).Set(float64(result.Summary.TotalChecks))
}
