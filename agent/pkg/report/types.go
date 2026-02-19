// Package report provides compliance report generation in multiple output formats
// including JSON, HTML, and terminal table.
package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/kubecomply/kubecomply/pkg/scanner"
)

// Format represents a supported report output format.
type Format string

const (
	FormatJSON  Format = "json"
	FormatHTML  Format = "html"
	FormatTable Format = "table"
)

// ParseFormat converts a string to a Format, returning an error for invalid values.
func ParseFormat(s string) (Format, error) {
	switch Format(strings.ToLower(s)) {
	case FormatJSON:
		return FormatJSON, nil
	case FormatHTML:
		return FormatHTML, nil
	case FormatTable:
		return FormatTable, nil
	default:
		return "", fmt.Errorf("unsupported report format: %q (valid: json, html, table)", s)
	}
}

// Reporter is the interface for generating compliance reports.
type Reporter interface {
	// Generate writes the scan result as a report to the writer.
	Generate(w io.Writer, result *scanner.ScanResult) error
}

// NewReporter creates a Reporter for the specified format.
func NewReporter(format Format) (Reporter, error) {
	switch format {
	case FormatJSON:
		return &JSONReporter{}, nil
	case FormatHTML:
		return &HTMLReporter{}, nil
	case FormatTable:
		return &TableReporter{}, nil
	default:
		return nil, fmt.Errorf("unsupported report format: %q", format)
	}
}
