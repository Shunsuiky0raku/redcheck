Overview

In today’s cybersecurity landscape, Red Hat Enterprise Linux (RHEL) and its downstream distributions (such as Rocky Linux) are widely deployed across enterprise, cloud, and government infrastructures due to their stability and strong vendor support. However, despite their robustness, these systems often suffer from overlooked misconfigurations, weak authentication policies, improper service settings, and outdated security controls. These issues frequently go unnoticed, especially in environments where administrators lack a lightweight, consistent, and fast method of evaluating system hardening.

While the Windows ecosystem benefits from mature tools like PingCastle for Active Directory security health checks, the Linux ecosystem lacks an equivalent streamlined tool for server posture assessment. Existing scanners such as OpenSCAP or Lynis are powerful but either too compliance-heavy, too broad, or too time-consuming for fast-paced operational or red team scenarios. As a result, system administrators and penetration testers often rely on manual checklists, which are error-prone, inconsistent, and rarely aligned with industry-recognized benchmarks such as the CIS (Center for Internet Security) Rocky Linux Benchmarks.

RedCheck directly addresses this gap.

RedCheck is a dual-use, high-speed command-line tool designed for auditing the security posture of RHEL-based systems. It evaluates a system against a curated subset of CIS Benchmark v10 controls and common privilege-escalation weaknesses. The tool produces a weighted security score, category-by-category breakdowns, and actionable remediation guidance—available in terminal output, JSON, and HTML formats. Its lightweight design makes it suitable for both defensive and offensive workflows.

Installation
1. Clone the repository
git clone https://github.com/Shunsuiky0raku/redcheck.git
cd redcheck

2. Build the binary
go build -o redcheck .

3. Run the tool (root recommended)
sudo ./redcheck scan --all


RedCheck requires elevated permissions to inspect system configuration, mount options, audit settings, and privileged files.

🧪 Usage Examples
Run all checks (default)
sudo ./redcheck scan --all

Run only CIS Benchmark checks
sudo ./redcheck scan --cis

Run only recon / privilege-escalation checks
sudo ./redcheck scan --pe

Export JSON report
sudo ./redcheck scan --all --json out.json

Generate HTML report
sudo ./redcheck scan --all --html out.html

Enable verbose evidence output
sudo ./redcheck scan --all -v

Load extra custom YAML rules
sudo ./redcheck scan --rules ./rules

Generate remediation script
sudo ./redcheck scan --all --emit-fix fix.sh

Enable shell auto-completion
./redcheck completion bash    # or zsh, fish, powershell

⚡ Full Feature List
✅ 1. High-Speed Modular Scanning Engine

Parses and evaluates CIS-aligned rules

Supports internal and external YAML rule definitions

Uses parallel execution (worker pool) for fast scanning

Runs cleanly on Rocky Linux / RHEL / CentOS

✅ 2. Severity-Weighted Scoring System

Assigns all checks a severity weight (Critical/High/Medium/Low)

Computes category-by-category scores

Produces a global security score weighted by category importance

Includes error penalties for inaccessible or misconfigured system files

✅ 3. Red-Team Reconnaissance Mode

Provides attacker-centric checks such as:

Sudo misconfigurations

Writable or insecure mount options

SSH misconfigurations

Accounts with UID 0

Missing audit controls

Potential privilege escalation paths

This mode gives penetration testers a lightweight alternative to tools like linPEAS.

✅ 4. Multi-Format Reporting

Terminal output (with top findings and remediation)

JSON report for machine-readable pipelines

HTML report with styling, progress bars, and detailed results

Optional evidence (-v) and optional fix script generation

✅ 5. Extensible Rule Framework

Users can add custom .yaml rules to check for:

Organization-specific hardening policies

Additional privilege escalation checks

Compliance controls not included by default

✅ 6. Clean User Interface

ASCII art banner

Real-time progress bar

Organized grouping of results

Top 5 fixes highlighted for quick action

📊 Theory Behind the Scoring System

RedCheck uses a hybrid scoring model inspired by:

CIS Benchmark structure & severity levels

NIST SP 800-30 risk scoring principles

NIST 800-53 control impact weighting

Your scoring approach consists of three core components:

1️⃣ Severity Weighting (Rule-Level)

Each rule has a severity:

Severity	Weight
Critical	4
High	3
Medium	2
Low	1

A failed High-severity rule reduces the score more than a Low-severity rule.

This ensures the score reflects risk, not just the number of failed checks.

2️⃣ Category Weighting (Domain-Level)
"Privileges": 30,
"Services":   20,
"Auth":       20,
"FS_Perms":   15,
"Audit":      10,
"Recon":       5,


This is based on security prioritization similar to NIST & CIS:

Privilege escalation risks matter MOST

Services & Auth are critical to attack surface

Filesystem permissions, audit controls matter moderately

Recon findings least weighted for global posture

3️⃣ Weighted Category Score Formula

For each category:

score = 100 – (failed_weight / total_weight) × 100


Example:

Max severity points = 20

Failed severity points = 10

→ Score = 50%

4️⃣ Global Score Calculation

Global score is a weighted sum:

global = Σ( category_score × category_weight ) / 100


This model ensures:

A strong score requires good performance across all categories

A severe failure in Privileges or Auth significantly impacts the score

Minor failures do not distort the global posture
