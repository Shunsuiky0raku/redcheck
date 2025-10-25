package cmd

import (
	"fmt"
	"github.com/Shunsuiky0raku/redcheck/pkg/checks"
	htmlreport "github.com/Shunsuiky0raku/redcheck/pkg/report/html"
	jsonreport "github.com/Shunsuiky0raku/redcheck/pkg/report/json"
	"github.com/Shunsuiky0raku/redcheck/pkg/scoring"
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	flagAll     bool
	flagCIS     bool
	flagPE      bool
	jsonOut     string
	htmlOut     string
	flagTimeout time.Duration
	flagJobs    int
	flagRules   string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run RedCheck scans",
	Long:  "Run CIS Rocky v10 checks and/or attacker-centric recon checks and produce JSON/HTML reports.",
	RunE: func(cmd *cobra.Command, args []string) error {
		// 1) default mode
		if !flagAll && !flagCIS && !flagPE {
			flagAll = true
		}

		// 2) load rules
		rs, err := checks.LoadRules()
		if err != nil {
			return err
		}

		builtIn := len(rs)
		extra := 0
		if flagRules != "" {
			dir := flagRules
			if !filepath.IsAbs(dir) {
				if cwd, _ := os.Getwd(); cwd != "" {
					dir = filepath.Join(cwd, dir)
				}
			}
			if erules, err := checks.LoadRulesFromDir(dir); err == nil && len(erules) > 0 {
				rs = append(rs, erules...)
				extra = len(erules)
			} else if err != nil {
				fmt.Println("[warn] failed to load extra rules:", err)
			}
		}
		fmt.Printf("Loaded %d built-in rules", builtIn)
		if extra > 0 {
			fmt.Printf(" + %d external rules", extra)
		}
		fmt.Println(".")

		// 3) select rules (all == cis for now; we'll add tags/pe later)
		sel := make([]checks.Rule, 0, len(rs))
		for _, r := range rs {
			if flagAll || flagCIS {
				sel = append(sel, r)
			}
		}

		// 4) evaluate
		// -------- 4) evaluate (concurrent with per-check timeout) --------
		if flagJobs <= 0 {
			flagJobs = runtime.NumCPU()
		}
		type job struct{ r checks.Rule }
		type out struct{ cr checks.CheckResult }

		jobs := make(chan job)
		outs := make(chan out)
		var wg sync.WaitGroup

		worker := func() {
			defer wg.Done()
			for j := range jobs {
				outs <- out{cr: evalWithTimeout(j.r, flagTimeout)}
			}
		}

		for i := 0; i < flagJobs; i++ {
			wg.Add(1)
			go worker()
		}
		go func() {
			for _, r := range sel {
				jobs <- job{r: r}
			}
			close(jobs)
		}()
		go func() { wg.Wait(); close(outs) }()

		results := make([]checks.CheckResult, 0, len(sel))
		for o := range outs {
			results = append(results, o.cr)
		}

		fmt.Printf("Evaluated %d rules.\n", len(results))
		fmt.Printf("Starting scan… (all=%v, cis=%v, pe=%v, timeout=%s, jobs=%d)\n",
			flagAll, flagCIS, flagPE, flagTimeout, flagJobs)

		// 5) compute scores (for terminal + HTML)
		resIface := make([]scoring.Result, len(results))
		for i := range results {
			resIface[i] = results[i]
		}
		scores := scoring.Compute(resIface)
		if os.Geteuid() != 0 {
			fmt.Println("\n[warn] running as non-root: some checks may be incomplete (marked error/na). Try 'sudo redcheck scan ...' for full coverage.")
		}

		// 6) terminal summary
		fmt.Printf("\nGlobal score: %.1f\n", scores.Global)
		fmt.Println("Category scores:")
		for _, cs := range scores.ByCategory {
			fmt.Printf("  - %-10s : %.1f\n", cs.Category, cs.Score)
		}
		// Top 5 fixes (by severity)
		sevRank := map[string]int{"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
		fails := make([]checks.CheckResult, 0, len(results))
		for _, r := range results {
			if r.Status == "fail" {
				fails = append(fails, r)
			}
		}
		sort.Slice(fails, func(i, j int) bool {
			si, sj := sevRank[fails[i].Severity], sevRank[fails[j].Severity]
			if si != sj {
				return si < sj
			}
			return fails[i].ID < fails[j].ID
		})
		if len(fails) > 5 {
			fails = fails[:5]
		}
		if len(fails) > 0 {
			fmt.Println("\nTop 5 fixes:")
			for _, f := range fails {
				fmt.Printf("  • [%s] %s — observed=%q → expected=%q\n", f.Category, f.Title, f.Observed, f.Expected)
				fmt.Printf("    Remediation: %s\n", f.Remediation)
			}
		} else {
			fmt.Println("\nNo failed checks 🎉")
		}

		// 7) write JSON (optional)
		if jsonOut != "" {
			if err := jsonreport.Write(jsonOut, results); err != nil {
				return err
			}
			fmt.Println("JSON written to:", jsonOut)
		}

		// 8) write HTML (optional)
		if htmlOut != "" {
			h, _ := os.Hostname()
			ts := time.Now().UTC().Format(time.RFC3339)
			if err := htmlreport.Write(htmlOut, h, ts, scores, results); err != nil {
				return err
			}
			fmt.Println("HTML written to:", htmlOut)
		}

		return nil
	},
}

// evalWithTimeout runs a single rule with a soft timeout.
// If it times out, we return an error-style CheckResult with Observed="timeout".
func evalWithTimeout(r checks.Rule, d time.Duration) checks.CheckResult {
	if d <= 0 {
		return checks.Evaluate(r)
	}
	ch := make(chan checks.CheckResult, 1)
	go func() { ch <- checks.Evaluate(r) }()
	select {
	case res := <-ch:
		return res
	case <-time.After(d):
		// fabricate a timeout result
		return checks.CheckResult{
			ID:          r.ID,
			Title:       r.Title,
			Category:    r.Category,
			Status:      "error",
			Observed:    "timeout",
			Expected:    firstExpected(r), // tiny helper below
			Severity:    r.Severity,
			Remediation: r.Remediation,
		}
	}
}

// firstExpected joins Expected/ExpectedAll to show something meaningful on timeout.
func firstExpected(r checks.Rule) string {
	if r.Expected != "" {
		return r.Expected
	}
	if len(r.ExpectedAll) > 0 {
		return strings.Join(r.ExpectedAll, ",")
	}
	return ""
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().BoolVar(&flagAll, "all", false, "Run all checks (default if none specified)")
	scanCmd.Flags().BoolVar(&flagCIS, "cis", false, "Run CIS benchmark checks only")
	scanCmd.Flags().BoolVar(&flagPE, "pe", false, "Run recon/priv-esc checks only")
	scanCmd.Flags().StringVar(&jsonOut, "json", "", "Write results to JSON file")
	scanCmd.Flags().StringVar(&htmlOut, "html", "", "Write report to HTML file")
	scanCmd.Flags().DurationVar(&flagTimeout, "timeout", 60*time.Second, "Per-check timeout (e.g., 60s, 2m)")
	scanCmd.Flags().IntVar(&flagJobs, "jobs", 0, "Number of parallel workers (default: CPU count)")
	scanCmd.Flags().StringVar(&flagRules, "rules", "", "Directory with extra rule files (*.yml, *.yaml)")
}
