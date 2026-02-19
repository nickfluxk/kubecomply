package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/kubecomply/kubecomply/pkg/scanner"
)

// ANSI color codes for terminal output.
const (
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
	colorGray    = "\033[90m"
	colorBold    = "\033[1m"
)

// TableReporter outputs scan results as a formatted terminal table with colors.
type TableReporter struct{}

// Generate writes the scan result as a terminal table.
func (r *TableReporter) Generate(w io.Writer, result *scanner.ScanResult) error {
	// Header.
	fmt.Fprintf(w, "\n%s%s KubeComply Compliance Report %s\n", colorBold, colorCyan, colorReset)
	fmt.Fprintf(w, "%s%s%s\n\n", colorGray, strings.Repeat("-", 60), colorReset)

	// Scan metadata.
	fmt.Fprintf(w, "  Cluster:   %s%s%s\n", colorBold, result.ClusterName, colorReset)
	fmt.Fprintf(w, "  Scan Type: %s%s%s\n", colorBold, result.ScanType, colorReset)
	fmt.Fprintf(w, "  Duration:  %s\n", result.Duration.String())
	fmt.Fprintf(w, "  Date:      %s\n\n", result.EndTime.Format("2006-01-02 15:04:05 UTC"))

	// Score bar.
	score := result.Summary.Score
	scoreColor := colorGreen
	if score < 50 {
		scoreColor = colorRed
	} else if score < 70 {
		scoreColor = colorYellow
	} else if score < 90 {
		scoreColor = colorCyan
	}

	barWidth := 40
	filled := int(score / 100.0 * float64(barWidth))
	if filled > barWidth {
		filled = barWidth
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

	fmt.Fprintf(w, "  Compliance Score: %s%s%.1f%%%s\n", colorBold, scoreColor, score, colorReset)
	fmt.Fprintf(w, "  %s%s%s\n\n", scoreColor, bar, colorReset)

	// Summary cards.
	fmt.Fprintf(w, "  %sChecks:%s %d total | %s%d passed%s | %s%d failed%s",
		colorBold, colorReset, result.Summary.TotalChecks,
		colorGreen, result.Summary.PassedChecks, colorReset,
		colorRed, result.Summary.FailedChecks, colorReset,
	)
	if result.Summary.WarningCount > 0 {
		fmt.Fprintf(w, " | %s%d warnings%s", colorYellow, result.Summary.WarningCount, colorReset)
	}
	fmt.Fprintln(w)

	// Severity breakdown.
	fmt.Fprintf(w, "  %sSeverity:%s ", colorBold, colorReset)
	sevCounts := result.Summary.FindingsBySeverity
	parts := []string{}
	if c := sevCounts[scanner.SeverityCritical]; c > 0 {
		parts = append(parts, fmt.Sprintf("%s%d critical%s", colorRed, c, colorReset))
	}
	if c := sevCounts[scanner.SeverityHigh]; c > 0 {
		parts = append(parts, fmt.Sprintf("%s%d high%s", colorMagenta, c, colorReset))
	}
	if c := sevCounts[scanner.SeverityMedium]; c > 0 {
		parts = append(parts, fmt.Sprintf("%s%d medium%s", colorYellow, c, colorReset))
	}
	if c := sevCounts[scanner.SeverityLow]; c > 0 {
		parts = append(parts, fmt.Sprintf("%s%d low%s", colorBlue, c, colorReset))
	}
	if c := sevCounts[scanner.SeverityInfo]; c > 0 {
		parts = append(parts, fmt.Sprintf("%s%d info%s", colorGray, c, colorReset))
	}
	if len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%sno findings%s", colorGreen, colorReset))
	}
	fmt.Fprintln(w, strings.Join(parts, " | "))
	fmt.Fprintln(w)

	// Findings table. Only show non-pass findings.
	failedFindings := make([]scanner.Finding, 0)
	for _, f := range result.Findings {
		if f.Status != scanner.StatusPass {
			failedFindings = append(failedFindings, f)
		}
	}

	// Sort by severity (most severe first).
	sort.Slice(failedFindings, func(i, j int) bool {
		ri := scanner.SeverityRank(failedFindings[i].Severity)
		rj := scanner.SeverityRank(failedFindings[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return failedFindings[i].ID < failedFindings[j].ID
	})

	if len(failedFindings) == 0 {
		fmt.Fprintf(w, "  %s%sAll checks passed!%s\n\n", colorBold, colorGreen, colorReset)
		return nil
	}

	fmt.Fprintf(w, "  %sFindings (%d):%s\n\n", colorBold, len(failedFindings), colorReset)

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "  %sID\tSEVERITY\tSTATUS\tCATEGORY\tTITLE\tRESOURCE%s\n", colorGray, colorReset)
	fmt.Fprintf(tw, "  %s--\t--------\t------\t--------\t-----\t--------%s\n", colorGray, colorReset)

	for _, f := range failedFindings {
		sevStr := colorSeverity(f.Severity)
		statusStr := colorStatus(f.Status)

		resource := f.Resource
		if f.Namespace != "" && !strings.Contains(resource, f.Namespace) {
			resource = f.Namespace + "/" + resource
		}
		// Truncate long resource names.
		if len(resource) > 50 {
			resource = resource[:47] + "..."
		}

		title := f.Title
		if len(title) > 55 {
			title = title[:52] + "..."
		}

		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\n",
			f.ID, sevStr, statusStr, f.Category, title, resource)
	}

	if err := tw.Flush(); err != nil {
		return fmt.Errorf("flushing table writer: %w", err)
	}

	fmt.Fprintln(w)
	return nil
}

func colorSeverity(s scanner.Severity) string {
	switch s {
	case scanner.SeverityCritical:
		return fmt.Sprintf("%s%sCRITICAL%s", colorBold, colorRed, colorReset)
	case scanner.SeverityHigh:
		return fmt.Sprintf("%sHIGH%s", colorMagenta, colorReset)
	case scanner.SeverityMedium:
		return fmt.Sprintf("%sMEDIUM%s", colorYellow, colorReset)
	case scanner.SeverityLow:
		return fmt.Sprintf("%sLOW%s", colorBlue, colorReset)
	case scanner.SeverityInfo:
		return fmt.Sprintf("%sINFO%s", colorGray, colorReset)
	default:
		return string(s)
	}
}

func colorStatus(s scanner.FindingStatus) string {
	switch s {
	case scanner.StatusPass:
		return fmt.Sprintf("%sPASS%s", colorGreen, colorReset)
	case scanner.StatusFail:
		return fmt.Sprintf("%sFAIL%s", colorRed, colorReset)
	case scanner.StatusWarning:
		return fmt.Sprintf("%sWARN%s", colorYellow, colorReset)
	case scanner.StatusError:
		return fmt.Sprintf("%sERROR%s", colorRed, colorReset)
	case scanner.StatusSkipped:
		return fmt.Sprintf("%sSKIP%s", colorGray, colorReset)
	default:
		return string(s)
	}
}
