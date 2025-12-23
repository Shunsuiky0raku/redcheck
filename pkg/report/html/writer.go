package htmlreport

import (
	"html/template"
	"os"
	"sort"

	"github.com/Shunsuiky0raku/redcheck/pkg/checks"
	"github.com/Shunsuiky0raku/redcheck/pkg/scoring"
)

type ViewModel struct {
	Hostname      string
	Time          string
	Scores        scoring.Scores
	Results       []checks.CheckResult
	TopFixes      []checks.CheckResult
	Version       string
	Commit        string
	BuildDate     string
	BuiltInRules  int
	ExternalRules int
	Jobs          int
	Timeout       string
	IsRoot        bool
}

// IMPORTANT: the HTML template must be a Go raw string (backticks)
const tpl = `<!doctype html>
<meta charset="utf-8">
<title>RedCheck Report</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Helvetica,Arial,sans-serif;margin:24px;line-height:1.4}
h1,h2{margin:0 0 8px}
.card{border:1px solid #eee;border-radius:12px;padding:16px;margin:12px 0}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px}
.pass{background:#e8f5e9} .fail{background:#ffebee} .error{background:#fff3e0} .na{background:#eceff1}
.row{display:flex;gap:12px;flex-wrap:wrap}
.bar{height:10px;background:#eee;border-radius:6px;overflow:hidden}
.fill{height:100%;background:#4caf50}
.small{color:#555;font-size:12px}
table{width:100%;border-collapse:collapse}
th,td{border-top:1px solid #eee;padding:8px;text-align:left;vertical-align:top}
code{background:#f6f8fa;padding:2px 4px;border-radius:4px}
.footer{margin-top:16px;color:#666;font-size:12px}
.header-meta{margin:8px 0;color:#444;font-size:13px}
.warn{background:#fff3cd;padding:10px;border-left:4px solid #ffc107;border-radius:6px;margin:8px 0}
button{padding:6px 10px;border:1px solid #ddd;border-radius:8px;background:#fafafa;cursor:pointer}
button:hover{background:#e8e8e8}
button.active{background:#4caf50;color:white;border-color:#4caf50}
select{padding:6px 10px;border:1px solid #ddd;border-radius:8px;background:#fafafa;cursor:pointer}
.controls{display:flex;gap:12px;margin:12px 0;flex-wrap:wrap;align-items:center}
.control-group{display:flex;gap:8px;align-items:center}
.fix-item{margin-bottom:8px;padding:8px;border-left:3px solid transparent;transition:all 0.2s}
.fix-item.hidden{display:none}
.category-badge{display:inline-block;padding:2px 6px;border-radius:4px;font-size:11px;margin-left:4px;font-weight:normal}
.cat-FS_Perms{background:#e3f2fd;color:#1976d2} .cat-Services{background:#f3e5f5;color:#7b1fa2}
.cat-Auth{background:#fff3e0;color:#f57c00} .cat-Privileges{background:#ffebee;color:#c62828}
.cat-Recon{background:#e8f5e9;color:#388e3c} .cat-Audit{background:#f1f8e9;color:#689f38}
</style>

<script>
let currentFilter = 'all';
let currentSort = 'severity';

function copyFixes(){
  const items = Array.from(document.querySelectorAll('td.rem')).map(td => td.innerText.trim());
  const seen = new Set();
  const cmds = items.filter(x => x).filter(x => (seen.has(x) ? false : seen.add(x)));
  if (cmds.length === 0) { alert('No remediation commands to copy.'); return; }
  navigator.clipboard.writeText(cmds.join('\n'))
    .then(()=>alert('All remediations copied to clipboard.'))
    .catch(()=>alert('Copy failed (clipboard not available).'));
}

function copyTopFixes(){
  const visibleItems = Array.from(document.querySelectorAll('.fix-item:not(.hidden)'));
  const cmds = visibleItems.map(item => {
    const remText = item.querySelector('.fix-remediation')?.innerText || '';
    return remText.replace(/^Remediation:\s*/i, '').trim();
  }).filter(x => x);
  if (cmds.length === 0) { alert('No remediation commands to copy from visible fixes.'); return; }
  navigator.clipboard.writeText(cmds.join('\n'))
    .then(()=>alert('Copied ' + cmds.length + ' remediation command(s) to clipboard.'))
    .catch(()=>alert('Copy failed (clipboard not available).'));
}

function filterFixes(category){
  currentFilter = category;
  const items = document.querySelectorAll('.fix-item');
  items.forEach(item => {
    if(category === 'all' || item.dataset.category === category){
      item.classList.remove('hidden');
    } else {
      item.classList.add('hidden');
    }
  });
  updateVisibleCount();
}

function sortFixes(method){
  currentSort = method;
  const container = document.getElementById('top-fixes-container');
  const items = Array.from(document.querySelectorAll('.fix-item'));
  
  items.sort((a, b) => {
    if(method === 'severity'){
      const sevOrder = {Critical: 0, High: 1, Medium: 2, Low: 3};
      const sevA = sevOrder[a.dataset.severity] || 999;
      const sevB = sevOrder[b.dataset.severity] || 999;
      if(sevA !== sevB) return sevA - sevB;
      return a.dataset.title.localeCompare(b.dataset.title);
    } else if(method === 'category'){
      const catCmp = a.dataset.category.localeCompare(b.dataset.category);
      if(catCmp !== 0) return catCmp;
      return a.dataset.title.localeCompare(b.dataset.title);
    } else if(method === 'ease'){
      const easeOrder = {low: 0, medium: 1, high: 2};
      const easeA = easeOrder[a.dataset.ease] || 1;
      const easeB = easeOrder[b.dataset.ease] || 1;
      if(easeA !== easeB) return easeA - easeB;
      return a.dataset.title.localeCompare(b.dataset.title);
    }
    return 0;
  });
  
  items.forEach(item => container.appendChild(item));
  updateSortButtons(method);
}

function updateSortButtons(activeMethod){
  document.querySelectorAll('.sort-btn').forEach(btn => {
    btn.classList.remove('active');
    if(btn.dataset.sort === activeMethod){
      btn.classList.add('active');
    }
  });
}

function updateVisibleCount(){
  const visible = document.querySelectorAll('.fix-item:not(.hidden)').length;
  const total = document.querySelectorAll('.fix-item').length;
  const counter = document.getElementById('visible-count');
  if(counter){
    counter.innerText = 'Showing ' + visible + ' of ' + total + ' fixes';
  }
}
</script>

<h1>RedCheck Report</h1>
<div class="header-meta">
  Host: {{.Hostname}} &middot; Time: {{.Time}} &middot;
  Built-in rules: {{.BuiltInRules}} {{if gt .ExternalRules 0}}+ External: {{.ExternalRules}}{{end}} &middot;
  Jobs: {{.Jobs}} &middot; Timeout: {{.Timeout}}
</div>

{{if not .IsRoot}}
<div class="warn">
  <b>Warning:</b> report generated as non-root. Some checks may be incomplete or marked <code>na</code>/<code>error</code>.
  For full coverage run with root privileges (e.g., <code>sudo ./redcheck scan ...</code>).
</div>
{{end}}

<div style="margin:8px 0">
  <button onclick="copyFixes()">Copy all remediation commands</button>
</div>

<div class="card">
  <h2>Score</h2>
  <div>Global: <b>{{printf "%.1f" .Scores.Global}}</b></div>
  {{range .Scores.ByCategory}}
    <div style="margin-top:8px">{{.Category}} — {{printf "%.1f" .Score}}
      <div class="bar"><div class="fill" style="width:{{printf "%.0f" .Score}}%"></div></div>
    </div>
  {{end}}
</div>

{{if .TopFixes}}
<div class="card">
  <h2>Top Fixes</h2>
  <div class="controls">
    <div class="control-group">
      <label for="category-filter"><b>Filter by Category:</b></label>
      <select id="category-filter" onchange="filterFixes(this.value)">
        <option value="all">All Categories</option>
        <option value="FS_Perms">FS_Perms</option>
        <option value="Services">Services</option>
        <option value="Auth">Auth</option>
        <option value="Privileges">Privileges</option>
        <option value="Recon">Recon</option>
        <option value="Audit">Audit</option>
      </select>
    </div>
    <div class="control-group">
      <label><b>Sort by:</b></label>
      <button class="sort-btn active" data-sort="severity" onclick="sortFixes('severity')">Severity</button>
      <button class="sort-btn" data-sort="category" onclick="sortFixes('category')">Category</button>
      <button class="sort-btn" data-sort="ease" onclick="sortFixes('ease')">Implementation Ease</button>
    </div>
    <div class="control-group">
      <button onclick="copyTopFixes()">Copy Visible Remediation Commands</button>
    </div>
  </div>
  <div class="small" id="visible-count" style="margin:8px 0;color:#666"></div>
  <div id="top-fixes-container">
  {{range .TopFixes}}
    <div class="fix-item" data-category="{{.Category}}" data-severity="{{.Severity}}" data-title="{{.Title}}" data-ease="{{if eq .Category "Services"}}low{{else if eq .Category "Auth"}}medium{{else if eq .Category "FS_Perms"}}low{{else}}medium{{end}}">
      <b>{{.Title}}</b> <span class="badge {{.Status}}">{{.Status}}</span><span class="category-badge cat-{{.Category}}">{{.Category}}</span>
      <div class="small">Observed: <code>{{.Observed}}</code> → Expected: <code>{{.Expected}}</code></div>
      <div class="small fix-remediation">Remediation: {{.Remediation}}</div>
      {{if .Evidence}}
        <div class="small"><details><summary>Evidence</summary><pre>{{.Evidence}}</pre></details></div>
      {{end}}
    </div>
  {{end}}
  </div>
</div>
<script>
  document.addEventListener('DOMContentLoaded', function() {
    updateVisibleCount();
    updateSortButtons('severity');
  });
</script>
{{end}}

<div class="card">
  <h2>All results</h2>
  <table>
    <thead><tr><th>ID</th><th>Title</th><th>Category</th><th>Status</th><th>Observed → Expected</th><th>Remediation</th></tr></thead>
    <tbody>
      {{range .Results}}
      <tr>
        <td><code>{{.ID}}</code></td>
        <td>{{.Title}}</td>
        <td>{{.Category}}</td>
        <td><span class="badge {{.Status}}">{{.Status}}</span></td>
        <td class="small"><code>{{.Observed}}</code> → <code>{{.Expected}}</code></td>
        <td class="small rem">
          {{.Remediation}}
          {{if .Evidence}}
            <div class="small"><details><summary>Evidence</summary><pre>{{.Evidence}}</pre></details></div>
          {{end}}
        </td>
      </tr>
      {{end}}
    </tbody>
  </table>
</div>

<div class="footer">
  Generated by RedCheck v{{.Version}} (commit {{.Commit}}, built {{.BuildDate}})
</div>
`

func Write(
	path, hostname, tstamp string,
	scores scoring.Scores,
	results []checks.CheckResult,
	builtIn, external, jobs int,
	timeout string, isRoot bool,
	version, commit, buildDate string,
) error {
	// pick Top 5 fails by severity
	fail := make([]checks.CheckResult, 0, len(results))
	for _, r := range results {
		if r.Status == "fail" {
			fail = append(fail, r)
		}
	}
	sevRank := map[string]int{"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
	sort.Slice(fail, func(i, j int) bool {
		si, sj := sevRank[fail[i].Severity], sevRank[fail[j].Severity]
		if si != sj {
			return si < sj
		}
		return fail[i].ID < fail[j].ID
	})
	// Show more fixes to make filtering/sorting more useful
	maxFixes := 10
	if len(fail) > maxFixes {
		fail = fail[:maxFixes]
	}

	vm := ViewModel{
		Hostname:      hostname,
		Time:          tstamp,
		Scores:        scores,
		Results:       results,
		TopFixes:      fail,
		Version:       version,
		Commit:        commit,
		BuildDate:     buildDate,
		BuiltInRules:  builtIn,
		ExternalRules: external,
		Jobs:          jobs,
		Timeout:       timeout,
		IsRoot:        isRoot,
	}

	t := template.Must(template.New("r").Parse(tpl))
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return t.Execute(f, vm)
}
