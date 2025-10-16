package scoring

import "strings"

// Category weights (v1 locked)
var Weights = map[string]float64{
	"Privileges": 30,
	"Services":   20,
	"Auth":       20,
	"FS_Perms":   15,
	"Audit":      10,
	"Recon":      5,
}

type Result interface {
	GetID() string
	GetSeverity() string
	GetStatus() string // "pass"|"fail"|"error"|"na"
	GetCategory() string
}

type CategoryScore struct {
	Category string  `json:"category"`
	Score    float64 `json:"score"` // 0..100
}

type Scores struct {
	Global     float64         `json:"global"`
	ByCategory []CategoryScore `json:"byCategory"`
}

// map severity to points
func sevPoints(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 1
	}
}

func Compute(results []Result) Scores {
	// per-category tallies
	type tallies struct{ max, failed, errPenalty int }
	cats := map[string]*tallies{}
	for c := range Weights {
		cats[c] = &tallies{}
	}

	// accumulate
	for _, r := range results {
		c := r.GetCategory()
		t, ok := cats[c]
		if !ok { // unknown category: bucket into Recon (smallest weight)
			c = "Recon"
			t = cats[c]
		}
		pts := sevPoints(r.GetSeverity())
		switch r.GetStatus() {
		case "pass", "na":
			// counted in max only if not NA
			if r.GetStatus() != "na" {
				t.max += pts
			}
		case "fail":
			t.max += pts
			t.failed += pts
		case "error":
			// count as small penalty without huge distortion
			t.errPenalty += 1
		}
	}

	// compute category scores 0..100
	out := Scores{}
	for cat, t := range cats {
		den := t.max
		if den <= 0 {
			// no applicable checks -> treat as 100 but don’t skew global weight
			out.ByCategory = append(out.ByCategory, CategoryScore{Category: cat, Score: 100})
			continue
		}
		// base score
		score := 100.0 - (float64(t.failed)/float64(den))*100.0
		// small transparency penalty per error
		if t.errPenalty > 0 && score > 0 {
			score -= float64(t.errPenalty) * 1.0
			if score < 0 {
				score = 0
			}
		}
		out.ByCategory = append(out.ByCategory, CategoryScore{Category: cat, Score: round1(score)})
	}

	// weighted global
	var total float64
	for _, cs := range out.ByCategory {
		w := Weights[cs.Category]
		total += (w * cs.Score) / 100.0
	}
	out.Global = round1(total)
	return out
}

func round1(v float64) float64 {
	return float64(int(v*10+0.5)) / 10.0
}
