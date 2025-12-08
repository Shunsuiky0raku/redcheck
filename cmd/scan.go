package cmd

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"

	"github.com/Shunsuiky0raku/redcheck/pkg/checks"
	htmlreport "github.com/Shunsuiky0raku/redcheck/pkg/report/html"
	jsonreport "github.com/Shunsuiky0raku/redcheck/pkg/report/json"
	"github.com/Shunsuiky0raku/redcheck/pkg/scoring"
)

var (
	flagAll         bool
	flagCIS         bool
	flagPE          bool
	flagVerbose     bool
	flagJobs        int
	flagTimeout     time.Duration
	flagJSON        string
	flagHTML        string
	flagRulesDir    string
	flagEmitFix     string
	flagInteractive bool

	// Remote scan flags
	flagSSHHost string
	flagSSHUser string
	flagSSHKey  string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run CIS and recon/priv-esc checks and produce JSON/HTML reports.",
	RunE: func(cmd *cobra.Command, args []string) error {
		// ── Remote mode: if ssh-host is set, delegate to a remote scan ────────────
		if flagSSHHost != "" {
			return runRemoteScan()
		}

		// ── Local mode (current behaviour) ───────────────────────────────────────
		// 1) decide what to run
		if !flagAll && !flagCIS && !flagPE {
			flagAll = true
		}

		checks.Verbose = flagVerbose

		// 2) load rules
		builtInRules, err := checks.LoadBuiltInRules()
		if err != nil {
			return fmt.Errorf("load built-in rules: %w", err)
		}

		var extraRules []checks.Rule
		if flagRulesDir != "" {
			extraRules, err = checks.LoadRulesFromDir(flagRulesDir)
			if err != nil {
				return fmt.Errorf("load extra rules from %q: %w", flagRulesDir, err)
			}
		}

		allRules := append([]checks.Rule{}, builtInRules...)
		allRules = append(allRules, extraRules...)

		activeRules := checks.FilterForMode(flagAll, flagCIS, flagPE, allRules)
		if len(activeRules) == 0 {
			return fmt.Errorf("no rules selected to run (check your flags)")
		}

		fmt.Printf("Loaded %d built-in rules", len(builtInRules))
		if len(extraRules) > 0 {
			fmt.Printf(" + %d external rules", len(extraRules))
		}
		fmt.Println(".")

		// 3) concurrency & timeout defaults
		if flagJobs <= 0 {
			flagJobs = runtime.NumCPU()
		}
		if flagJobs < 1 {
			flagJobs = 1
		}
		if flagTimeout <= 0 {
			flagTimeout = time.Minute
		}

		bar := progressbar.NewOptions(
			len(activeRules),
			progressbar.OptionSetDescription("Running checks"),
			progressbar.OptionSetPredictTime(false),
			progressbar.OptionClearOnFinish(),
		)

		results := make([]checks.CheckResult, len(activeRules))
		jobs := make(chan int)
		var wg sync.WaitGroup

		for i := 0; i < flagJobs; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for idx := range jobs {
					rule := activeRules[idx]
					res := checks.EvaluateWithTimeout(rule, flagTimeout)
					results[idx] = res
					_ = bar.Add(1)
				}
			}()
		}

		go func() {
			for i := range activeRules {
				jobs <- i
			}
			close(jobs)
		}()

		wg.Wait()
		_ = bar.Finish()

		fmt.Printf("Evaluated %d rules.\n", len(activeRules))
		fmt.Printf("Starting scan… (all=%v, cis=%v, pe=%v, timeout=%s, jobs=%d)\n\n",
			flagAll, flagCIS, flagPE, flagTimeout, flagJobs)

		// 4) scoring
		printScoreLegend()

		var asResults []scoring.Result
		for i := range results {
			if results[i].ID == "" {
				continue
			}
			asResults = append(asResults, results[i])
		}

		scores := scoring.Compute(asResults)
		printScoreSummary(scores)

		// 5) failed checks (top 5)
		failed := make([]checks.CheckResult, 0)
		for _, r := range results {
			if strings.EqualFold(r.Status, "fail") {
				failed = append(failed, r)
			}
		}

		if len(failed) > 0 {
			fmt.Println()
			fmt.Println("Top 5 fixes:")

			sort.Slice(failed, func(i, j int) bool {
				wi := severityWeight(failed[i].Severity)
				wj := severityWeight(failed[j].Severity)
				if wi == wj {
					// stable-ish by ID
					return failed[i].ID < failed[j].ID
				}
				return wi > wj
			})

			limit := 5
			if len(failed) < limit {
				limit = len(failed)
			}

			for i := 0; i < limit; i++ {
				f := failed[i]
				exp := f.Expected
				if strings.TrimSpace(exp) == "" {
					exp = "<see rule>"
				}
				fmt.Printf("  • [%s] %s — observed=%q → expected=%q\n",
					f.Category, f.Title, f.Observed, exp)

				if f.Remediation != "" {
					fmt.Printf("    Remediation: %s\n", f.Remediation)
				}
				if f.FilePath != "" {
					fmt.Printf("    Config file: %s\n", f.FilePath)
				}
			}
		} else {
			fmt.Println("No failed checks 🎉")
		}

		// 6) auto-fix / interactive mode
		if flagEmitFix != "" {
			if err := writeFixScript(flagEmitFix, results); err != nil {
				return err
			}
			fmt.Printf("Fix script written to: %s\n", flagEmitFix)
		} else if flagInteractive && len(failed) > 0 {
			if err := runInteractiveHardening(results); err != nil {
				return err
			}
		}

		// 7) reports (JSON / HTML)
		hostname, _ := os.Hostname()
		tstamp := time.Now().UTC().Format(time.RFC3339)
		version, commit, buildDate := buildVersion()

		if flagJSON != "" {
			if err := jsonreport.Write(flagJSON, results, hostname, tstamp, version, commit, buildDate); err != nil {
				return fmt.Errorf("write JSON report: %w", err)
			}
			fmt.Printf("JSON written to: %s\n", flagJSON)
		}

		if flagHTML != "" {
			isRoot := os.Geteuid() == 0
			if err := htmlreport.Write(
				flagHTML,
				hostname,
				tstamp,
				scores,
				results,
				len(builtInRules),
				len(extraRules),
				flagJobs,
				flagTimeout.String(),
				isRoot,
				version,
				commit,
				buildDate,
			); err != nil {
				return fmt.Errorf("write HTML report: %w", err)
			}
			fmt.Printf("HTML written to: %s\n", flagHTML)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().BoolVar(&flagAll, "all", false, "Run all checks (default if none specified)")
	scanCmd.Flags().BoolVar(&flagCIS, "cis", false, "Run CIS benchmark checks only")
	scanCmd.Flags().BoolVar(&flagPE, "pe", false, "Run recon/priv-esc checks only")
	scanCmd.Flags().BoolVarP(&flagVerbose, "verbose", "v", false, "Include evidence for failed checks")

	scanCmd.Flags().IntVar(&flagJobs, "jobs", 0, "Number of parallel workers (default: CPU count)")
	scanCmd.Flags().DurationVar(&flagTimeout, "timeout", time.Minute, "Per-check timeout (e.g., 60s, 2m)")

	scanCmd.Flags().StringVar(&flagJSON, "json", "", "Write results to JSON file")
	scanCmd.Flags().StringVar(&flagHTML, "html", "", "Write report to HTML file")
	scanCmd.Flags().StringVar(&flagRulesDir, "rules", "", "Directory with extra rule files (*.yml, *.yaml)")
	scanCmd.Flags().StringVar(&flagEmitFix, "emit-fix", "", "Write remediation script to this path (no execution)")
	scanCmd.Flags().BoolVar(&flagInteractive, "interactive", false, "Interactive mode to review and generate a fix.sh script (experimental)")

	// Remote flags
	scanCmd.Flags().StringVar(&flagSSHHost, "ssh-host", "", "Remote host to scan via SSH (requires redcheck on remote PATH)")
	scanCmd.Flags().StringVar(&flagSSHUser, "ssh-user", "", "SSH user for remote scan (default: current user)")
	scanCmd.Flags().StringVar(&flagSSHKey, "ssh-key", "", "SSH private key for remote scan (optional)")
}

// ── scoring helpers ────────────────────────────────────────────────────────────

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorGreen  = "\033[32m"
	colorCyan   = "\033[36m"
)

func colorForScore(s float64) string {
	switch {
	case s >= 80:
		return colorGreen
	case s >= 50:
		return colorYellow
	default:
		return colorRed
	}
}

func printScoreLegend() {
	fmt.Println("Score interpretation:")
	fmt.Println("  100%   → Fully secure / Compliant")
	fmt.Println("  80–99% → Strong posture")
	fmt.Println("  50–79% → Moderate risk")
	fmt.Println("  20–49% → Weak security")
	fmt.Println("  0–19%  → Critical risk (multiple high-severity failures)")
	fmt.Println()
	fmt.Println("Note: Severity (High/Medium/Low) influences the weighted score.")
	fmt.Println()
}

func printScoreSummary(scores scoring.Scores) {
	fmt.Printf("Global score: %s%.1f%s\n", colorForScore(scores.Global), scores.Global, colorReset)
	fmt.Println("Category scores:")

	cats := append([]scoring.CategoryScore(nil), scores.ByCategory...)
	sort.Slice(cats, func(i, j int) bool { return cats[i].Category < cats[j].Category })

	for _, cs := range cats {
		fmt.Printf("  - %-10s: %s%.1f%s\n", cs.Category, colorForScore(cs.Score), cs.Score, colorReset)
	}
	fmt.Println()
}

func severityWeight(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 3
	case "high":
		return 2
	case "medium":
		return 1
	default:
		return 0
	}
}

// ── fix.sh generation & interactive mode ──────────────────────────────────────

func writeFixScript(path string, results []checks.CheckResult) error {
	script := checks.BuildFixScript(results)
	if strings.TrimSpace(script) == "" {
		return fmt.Errorf("no fixes to emit; script would be empty")
	}

	// Make sure directory exists
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create directory %q: %w", dir, err)
		}
	}

	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		return fmt.Errorf("write fix script: %w", err)
	}
	return nil
}

func runInteractiveHardening(results []checks.CheckResult) error {
	failed := make([]checks.CheckResult, 0)
	for _, r := range results {
		if strings.EqualFold(r.Status, "fail") {
			failed = append(failed, r)
		}
	}
	if len(failed) == 0 {
		fmt.Println("No failed checks to review in interactive mode.")
		return nil
	}

	fmt.Println()
	fmt.Println("Interactive hardening mode (experimental).")
	fmt.Println("This mode will generate a fix script but WILL NOT execute it automatically.")
	fmt.Println()

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Generate fix.sh with proposed remediations now? [y/N]: ")
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	if line != "y" && line != "yes" {
		fmt.Println("Skipping fix.sh generation.")
		return nil
	}

	path := "fix.sh"
	if err := writeFixScript(path, results); err != nil {
		return err
	}
	fmt.Printf("Fix script written to: %s\n", path)
	fmt.Println("Review it carefully before running, especially on production systems.")
	return nil
}

// ── remote scan via SSH ───────────────────────────────────────────────────────

func runRemoteScan() error {
	if flagSSHHost == "" {
		return fmt.Errorf("ssh-host is required for remote scan")
	}

	user := flagSSHUser
	if user == "" {
		user = os.Getenv("USER")
		if user == "" {
			user = "root"
		}
	}

	dest := fmt.Sprintf("%s@%s", user, flagSSHHost)

	// Build remote `redcheck scan` arguments
	remoteArgs := []string{"redcheck", "scan"}

	if flagAll {
		remoteArgs = append(remoteArgs, "--all")
	}
	if flagCIS {
		remoteArgs = append(remoteArgs, "--cis")
	}
	if flagPE {
		remoteArgs = append(remoteArgs, "--pe")
	}
	if flagVerbose {
		remoteArgs = append(remoteArgs, "--verbose")
	}
	if flagJSON != "" {
		remoteArgs = append(remoteArgs, "--json", flagJSON)
	}
	if flagHTML != "" {
		remoteArgs = append(remoteArgs, "--html", flagHTML)
	}
	if flagRulesDir != "" {
		remoteArgs = append(remoteArgs, "--rules", flagRulesDir)
	}
	if flagEmitFix != "" {
		remoteArgs = append(remoteArgs, "--emit-fix", flagEmitFix)
	}
	if flagInteractive {
		remoteArgs = append(remoteArgs, "--interactive")
	}
	if flagJobs > 0 {
		remoteArgs = append(remoteArgs, "--jobs", fmt.Sprintf("%d", flagJobs))
	}
	if flagTimeout > 0 {
		remoteArgs = append(remoteArgs, "--timeout", flagTimeout.String())
	}

	fmt.Printf("%s[remote]%s Connecting to %s\n", colorCyan, colorReset, dest)
	fmt.Printf("%s[remote]%s Running: %s\n\n", colorCyan, colorReset, strings.Join(remoteArgs, " "))

	// Build ssh command: ssh [-i key] user@host redcheck scan ...
	sshArgs := []string{}
	if flagSSHKey != "" {
		sshArgs = append(sshArgs, "-i", flagSSHKey)
	}
	sshArgs = append(sshArgs, dest)
	sshArgs = append(sshArgs, remoteArgs...)

	cmd := exec.Command("ssh", sshArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	return cmd.Run()
}

