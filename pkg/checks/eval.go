package checks

import (
	"context"
	"time"
)

// EvaluateWithTimeout runs a single rule with a timeout and dynamic fact collection.
func EvaluateWithTimeout(rule Rule, timeout time.Duration) CheckResult {
	// Per-rule timeout guard (mainly for slower fact collectors / future exec checks)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	resultCh := make(chan CheckResult, 1)

	go func() {
		// 1) Collect facts for THIS rule (fact-centric engine)
		facts, evidence := gatherFactsForRule(rule, timeout)

		// 2) Evaluate rule against collected facts
		res := EvaluateRule(rule, facts)

		// 3) Attach evidence if verbose mode is enabled
		if Verbose && evidence != "" && res.Evidence == "" {
			res.Evidence = evidence
		}

		select {
		case resultCh <- res:
		case <-ctx.Done():
			// context timed out, do nothing; caller will handle timeout
		}
	}()

	select {
	case <-ctx.Done():
		// Hard timeout hit – mark as error
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

// MAIN EVALUATION LOGIC (pure comparison; facts are already resolved)
func EvaluateRule(rule Rule, facts map[string]string) CheckResult {
	observed := ""
	if facts != nil {
		observed = facts[rule.Fact]
	}

	// If we have files[] but no single FilePath, pick the first one
	filePath := rule.FilePath
	if filePath == "" && len(rule.Files) > 0 {
		filePath = rule.Files[0]
	}

	result := CheckResult{
		ID:          rule.ID,
		Title:       rule.Title,
		Category:    rule.Category,
		Severity:    rule.Severity,
		Observed:    observed,
		Expected:    rule.Expected,
		Remediation: rule.Remediation,
		FilePath:    filePath,
		Tags:        rule.Tags,
	}

	// ALL-OF rules (expected_all)
	if len(rule.ExpectedAll) > 0 {
		missing := evaluateAllOf(observed, rule.ExpectedAll)
		if len(missing) == 0 {
			result.Status = "pass"
		} else {
			result.Status = "fail"
			// For ALL-OF rules, Expected is a comma-joined list
			result.Expected = joinExpected(rule.ExpectedAll)
		}
		return result
	}

	// Simple rule: if no explicit expectation, treat as "info" pass
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
