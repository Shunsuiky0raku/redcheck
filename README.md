# RedCheck — Dual-Use Security Posture Scanner for RHEL-based Systems

RedCheck is a high-speed, dual-use security posture scanner for **Red Hat Enterprise Linux (RHEL)** and downstream distributions such as **Rocky Linux**. It helps:

- **System administrators / blue teams** validate hardening against a curated subset of **CIS Benchmark controls**
- **Penetration testers / red teams** quickly identify common **local misconfigurations & privilege-escalation signals**

It generates a **severity-weighted security score**, category breakdowns, and actionable remediation guidance in:
**terminal**, **JSON**, and **HTML**.

> ✅ **Read-only by default**  
> ⚠️ **Root recommended** (required for many checks: mounts, audit, privileged paths, system config)

---

## Why RedCheck?

RHEL is widely deployed across enterprise and government environments due to stability and vendor support, yet security misconfigurations still occur in real systems (weak authentication policies, insecure services, permissive file permissions, and privilege escalation paths).

Existing tools are powerful but fragmented:

- Compliance-heavy auditing (e.g., OpenSCAP / Lynis)
- Offensive post-exploitation enumeration (e.g., linPEAS)
- Manual checklists (error-prone and inconsistent)

RedCheck bridges this gap with a single lightweight CLI that supports both **defensive** and **attacker-view** posture assessment.

---

## Quick Start

### Build from source

```bash
git clone https://github.com/Shunsuiky0raku/redcheck.git
cd redcheck
go build -o redcheck .


```
## Run a full scan
```
sudo ./redcheck scan --all
```
## Run CIS checks only:
```
sudo ./redcheck scan --cis
```

## Run privilege escalation / recon checks only:
```
sudo ./redcheck scan --pe
```

## Export JSON report:
```
sudo ./redcheck scan --all --json out.json
```

## Generate HTML report:
```
sudo ./redcheck scan --all --html out.html
```

## Enable verbose evidence output:
```
sudo ./redcheck scan --all -v
```

## Load extra custom YAML rules:
```
sudo ./redcheck scan --rules ./rules
```

## Generate a remediation script (review before running):
```
sudo ./redcheck scan --all --emit-fix fix.sh
```

## Enable shell auto-completion:
```
./redcheck completion bash   # or zsh, fish, powershell
```
## Features
1) High-Speed Modular Scanning Engine

- Parses and evaluates CIS-aligned rules

- Supports internal and external YAML rule definitions

- Uses parallel execution (worker pool) for fast scanning

- Runs on Rocky Linux / RHEL / CentOS (RHEL-based systems)

2) Severity-Weighted Scoring System

- Assigns checks a severity weight (Critical/High/Medium/Low)

- Computes category-by-category scores

- Produces a global security score weighted by category importance

- Optional penalties for inaccessible or misconfigured system files

3) Red-Team Reconnaissance Mode
Attacker-centric checks such as:

- Sudo misconfigurations

- Writable or insecure mount options

- SSH misconfigurations

- Accounts with UID 0

- Missing audit controls

- Potential privilege escalation paths

A lightweight alternative to post-exploitation enumeration scripts (e.g., linPEAS), with more curated results.

4) Multi-Format Reporting

- Terminal output (top findings + remediation)

- JSON report for automation pipelines

- HTML report with styling, progress bars, and detailed results

- Optional evidence (-v) and optional fix script generation

5) Extensible Rule Framework

Add custom .yaml rules to check for:

- Organization-specific hardening policies

- Additional privilege escalation checks

- Compliance controls not included by default

6) Clean CLI Experience

- Organized grouping of results

- “Top fixes” highlighted for quick action

## Scoring Model

RedCheck uses a hybrid scoring model inspired by CIS structure and risk-based weighting.

1) Severity Weighting (Rule-level)
Severity	Weight
Critical	4
High	3
Medium	2
Low	1

A failed high-severity rule impacts the score more than a low-severity rule.

2) Category Weighting (Domain-level)

Example category weights:

Privileges: 30

Services: 20

Auth: 20

FS_Perms: 15

Audit: 10

Recon: 5


3) Category Score Formula

For each category:

score = 100 - (failed_weight / total_weight) * 100


Example:

Max severity points = 20

Failed severity points = 10
→ Category score = 50%

4) Global Score

Global score is a weighted sum:

global = Σ(category_score * category_weight) / 100


## Safety & Ethics

Read-only by default

No exploitation, persistence, or weaponization features

Use only on systems you own or have explicit authorization to assess
