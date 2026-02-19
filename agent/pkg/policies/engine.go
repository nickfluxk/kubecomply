package policies

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"

	"github.com/kubecomply/kubecomply/pkg/scanner"
)

// Engine loads and evaluates OPA/Rego policies against Kubernetes resources.
// It implements the scanner.PolicyEvaluator interface.
type Engine struct {
	mu      sync.RWMutex
	modules map[string]string // module name -> rego source
	bundles []PolicyBundle
	logger  *slog.Logger
}

// NewEngine creates a new policy evaluation engine.
func NewEngine(logger *slog.Logger) *Engine {
	if logger == nil {
		logger = slog.Default()
	}
	return &Engine{
		modules: make(map[string]string),
		logger:  logger,
	}
}

// LoadFromFS loads all .rego files from an fs.FS (useful for embed.FS).
func (e *Engine) LoadFromFS(fsys fs.FS, root string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	return fs.WalkDir(fsys, root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".rego") {
			return nil
		}
		// Skip test files.
		if strings.HasSuffix(path, "_test.rego") {
			return nil
		}

		data, readErr := fs.ReadFile(fsys, path)
		if readErr != nil {
			return fmt.Errorf("reading policy %s: %w", path, readErr)
		}

		moduleName := strings.TrimSuffix(path, ".rego")
		moduleName = strings.ReplaceAll(moduleName, string(filepath.Separator), ".")
		e.modules[moduleName] = string(data)
		e.logger.Debug("loaded policy module", "module", moduleName, "path", path)
		return nil
	})
}

// LoadFromDirectory loads all .rego files from a filesystem directory.
func (e *Engine) LoadFromDirectory(dir string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("policy directory %s: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("policy path %s is not a directory", dir)
	}

	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".rego") {
			return nil
		}
		if strings.HasSuffix(path, "_test.rego") {
			return nil
		}

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return fmt.Errorf("reading policy %s: %w", path, readErr)
		}

		relPath, _ := filepath.Rel(dir, path)
		moduleName := strings.TrimSuffix(relPath, ".rego")
		moduleName = strings.ReplaceAll(moduleName, string(filepath.Separator), ".")
		e.modules[moduleName] = string(data)
		e.logger.Debug("loaded policy module", "module", moduleName, "path", path)
		return nil
	})
}

// LoadInlinePolicy loads a single policy from a string.
func (e *Engine) LoadInlinePolicy(name, regoSource string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Validate the Rego source compiles.
	_, err := ast.ParseModule(name, regoSource)
	if err != nil {
		return fmt.Errorf("invalid rego in policy %s: %w", name, err)
	}

	e.modules[name] = regoSource
	e.logger.Debug("loaded inline policy", "module", name)
	return nil
}

// AddBundle registers a policy bundle with the engine.
func (e *Engine) AddBundle(bundle PolicyBundle) {
	e.mu.Lock()
	defer e.mu.Unlock()

	for name, source := range bundle.RegoModules {
		e.modules[name] = source
	}
	e.bundles = append(e.bundles, bundle)
	e.logger.Info("added policy bundle", "name", bundle.Name, "policies", len(bundle.Policies))
}

// ModuleCount returns the number of loaded policy modules.
func (e *Engine) ModuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.modules)
}

// Evaluate runs all loaded policies against the given input and returns check results.
// The query should target a rule that produces violation objects.
// A typical query is "data.compliance.violations" or a category-specific path.
func (e *Engine) Evaluate(ctx context.Context, input *PolicyEvalInput, query string) ([]CheckResult, error) {
	e.mu.RLock()
	modules := make(map[string]string, len(e.modules))
	for k, v := range e.modules {
		modules[k] = v
	}
	e.mu.RUnlock()

	if len(modules) == 0 {
		e.logger.Warn("no policy modules loaded, skipping OPA evaluation")
		return nil, nil
	}

	// Build rego options.
	opts := []func(*rego.Rego){
		rego.Query(query),
		rego.Input(input),
	}
	for name, source := range modules {
		opts = append(opts, rego.Module(name+".rego", source))
	}

	r := rego.New(opts...)

	rs, err := r.Eval(ctx)
	if err != nil {
		return nil, fmt.Errorf("OPA evaluation failed: %w", err)
	}

	return e.parseResults(rs)
}

// EvaluateResource satisfies the scanner.PolicyEvaluator interface.
// It wraps a single resource in PolicyEvalInput, evaluates it, and returns
// scanner.PolicyCheckResult values.
func (e *Engine) EvaluateResource(ctx context.Context, resource interface{}, namespace string, query string) ([]scanner.PolicyCheckResult, error) {
	input := &PolicyEvalInput{
		Resource:  resource,
		Namespace: namespace,
	}
	checks, err := e.Evaluate(ctx, input, query)
	if err != nil {
		return nil, err
	}

	results := make([]scanner.PolicyCheckResult, len(checks))
	for i, c := range checks {
		results[i] = scanner.PolicyCheckResult{
			ID:          c.ID,
			Title:       c.Title,
			Description: c.Description,
			Severity:    c.Severity,
			Passed:      c.Passed,
			Message:     c.Message,
			Resource:    c.Resource,
			Namespace:   c.Namespace,
			Remediation: c.Remediation,
			Category:    c.Category,
		}
	}
	return results, nil
}

// parseResults converts OPA result sets into CheckResult slices.
func (e *Engine) parseResults(rs rego.ResultSet) ([]CheckResult, error) {
	var results []CheckResult

	for _, result := range rs {
		for _, expr := range result.Expressions {
			violations, ok := expr.Value.([]interface{})
			if !ok {
				// Try as a set.
				if set, setOk := expr.Value.(map[string]interface{}); setOk {
					for _, v := range set {
						if cr, parseErr := e.parseViolation(v); parseErr == nil {
							results = append(results, cr)
						}
					}
					continue
				}
				e.logger.Debug("unexpected OPA result type", "type", fmt.Sprintf("%T", expr.Value))
				continue
			}

			for _, v := range violations {
				cr, parseErr := e.parseViolation(v)
				if parseErr != nil {
					e.logger.Warn("failed to parse violation", "error", parseErr)
					continue
				}
				results = append(results, cr)
			}
		}
	}

	return results, nil
}

// parseViolation extracts a CheckResult from an OPA violation value.
func (e *Engine) parseViolation(v interface{}) (CheckResult, error) {
	obj, ok := v.(map[string]interface{})
	if !ok {
		// If it's a string, treat it as a simple violation message.
		if msg, strOk := v.(string); strOk {
			return CheckResult{
				Title:    "Policy Violation",
				Message:  msg,
				Passed:   false,
				Severity: scanner.SeverityMedium,
			}, nil
		}
		return CheckResult{}, fmt.Errorf("violation is not a map: %T", v)
	}

	cr := CheckResult{
		Passed: false,
	}

	if id, ok := obj["id"].(string); ok {
		cr.ID = id
	}
	if title, ok := obj["title"].(string); ok {
		cr.Title = title
	}
	if msg, ok := obj["msg"].(string); ok {
		cr.Message = msg
	}
	if desc, ok := obj["description"].(string); ok {
		cr.Description = desc
	}
	if sev, ok := obj["severity"].(string); ok {
		if parsed, err := scanner.ParseSeverity(sev); err == nil {
			cr.Severity = parsed
		}
	}
	if cr.Severity == "" {
		cr.Severity = scanner.SeverityMedium
	}
	if res, ok := obj["resource"].(string); ok {
		cr.Resource = res
	}
	if ns, ok := obj["namespace"].(string); ok {
		cr.Namespace = ns
	}
	if rem, ok := obj["remediation"].(string); ok {
		cr.Remediation = rem
	}
	if cat, ok := obj["category"].(string); ok {
		cr.Category = cat
	}

	return cr, nil
}
