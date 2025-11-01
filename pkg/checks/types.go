package checks

type CheckResult struct {
	ID, Title, Category string
	Status              string
	Observed, Expected  string
	Severity            string
	Remediation         string
	Evidence            string // optional proof text when --verbose
}
