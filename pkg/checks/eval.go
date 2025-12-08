package checks

import (
	"context"
	"strings"
	"time"
)

// EvaluateWithTimeout runs a rule with a timeout.
func EvaluateWithTimeout(rule Rule, timeout time.Duration) CheckResult {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	resultCh := make(chan CheckResult, 1)

	go func() {
		// FIX: call EvaluateRule instead of undefined Evaluate()
		resultCh <- EvaluateRule(rule, nil)
	}()

	select {
	case <-ctx.Done():
		return CheckResult{
			ID:       rule.ID,
			Title:    rule.Title,
			Category: rule.Category,
			Status:   "error",
			Observed: "timeout",
			Expected: rule.Expected,
			Severity: rule.Severity,
		}
	case r := <-resultCh:
		return r
	}
}

// MAIN EVALUATION LOGIC
func EvaluateRule(rule Rule, facts map[string]string) CheckResult {

	observed := ""
	if facts != nil {
		observed = facts[rule.Fact]
	}

	result := CheckResult{
		ID:          rule.ID,
		Title:       rule.Title,
		Category:    rule.Category,
		Severity:    rule.Severity,
		Observed:    observed,
		Expected:    rule.Expected,
		Remediation: rule.Remediation,
		FilePath:    rule.FilePath,
		Tags:        rule.Tags,
	}

	// ALL-OF rules
	if len(rule.ExpectedAll) > 0 {
		missing := []string{}
		for _, want := range rule.ExpectedAll {
			if !strings.Contains(observed, want) {
				missing = append(missing, want)
			}
		}

		if len(missing) == 0 {
			result.Status = "pass"
		} else {
			result.Status = "fail"
			result.Expected = strings.Join(rule.ExpectedAll, ",")
		}
		return result
	}

	// Simple rule
	if rule.Expected == "" {
		result.Status = "pass"
		return result
	}

	if observed == rule.Expected {
		result.Status = "pass"
	} else {
		result.Status = "fail"
	}

	return result
}

