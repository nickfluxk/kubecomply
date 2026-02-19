package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/kubecomply/kubecomply/pkg/scanner"
)

// JSONReporter outputs scan results as formatted JSON.
type JSONReporter struct{}

// Generate writes the scan result as pretty-printed JSON.
func (r *JSONReporter) Generate(w io.Writer, result *scanner.ScanResult) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)

	if err := encoder.Encode(result); err != nil {
		return fmt.Errorf("encoding JSON report: %w", err)
	}

	return nil
}
