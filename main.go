package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var db *pgxpool.Pool

// Secrets come from the environment. Nothing sensitive lives in this file any more.
var (
	secretKey     string // signs activation tokens
	adminPassword string // dashboard password
	sessionSecret []byte // signs the admin cookie
)

const sessionHours = 12

type ActivationRequest struct {
	Key      string `json:"key"`
	DeviceID string `json:"device_id"`
	Token    string `json:"token,omitempty"`
}

type ActivationResponse struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
	Token  string `json:"token,omitempty"`
	Used   int    `json:"used,omitempty"`
	Limit  int    `json:"limit,omitempty"`
}

func generateToken(deviceID string) string {
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte(deviceID))
	return hex.EncodeToString(mac.Sum(nil))
}

func main() {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL environment variable is not set")
	}
	adminPassword = os.Getenv("ADMIN_PASSWORD")
	if adminPassword == "" {
		log.Fatal("ADMIN_PASSWORD environment variable is not set")
	}
	secretKey = os.Getenv("LICENSE_SECRET")
	if secretKey == "" {
		log.Fatal("LICENSE_SECRET environment variable is not set")
	}
	sessionSecret = []byte(secretKey + "|admin-session")

	var err error
	// Supabase's pooler (port 6543) runs in transaction mode and shares backend
	// connections between clients, so pgx's prepared-statement cache collides:
	//   prepared statement "stmtcache_..." already exists (42P05)
	// The simple protocol sends everything in one round trip and keeps no
	// server-side state, which is what the pooler needs.
	cfg, cfgErr := pgxpool.ParseConfig(dbURL)
	if cfgErr != nil {
		log.Fatalf("Invalid DATABASE_URL: %v\n", cfgErr)
	}
	cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	db, err = pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		log.Fatalf("Unable to connect to database: %v\n", err)
	}
	defer db.Close()

	http.HandleFunc("/", handleDashboard)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/set-name", handleSetName)
	http.HandleFunc("/revoke", handleRevoke)
	http.HandleFunc("/restore", handleRestore)
	http.HandleFunc("/delete", handleDeleteKey)
	http.HandleFunc("/activate", handleActivate)
	http.HandleFunc("/verify", handleVerify)
	http.HandleFunc("/usage", handleUsage)
	http.HandleFunc("/quota", handleQuota)
	http.HandleFunc("/set-credits", handleSetCredits)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	fmt.Printf("License server listening on port %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// ==========================================
// SESSION: signed cookie, not the word "authenticated"
// ==========================================
func makeSession() string {
	exp := time.Now().Add(sessionHours * time.Hour).Unix()
	payload := strconv.FormatInt(exp, 10)
	mac := hmac.New(sha256.New, sessionSecret)
	mac.Write([]byte(payload))
	return payload + "." + hex.EncodeToString(mac.Sum(nil))
}

func validSession(r *http.Request) bool {
	c, err := r.Cookie("admin_session")
	if err != nil {
		return false
	}
	parts := strings.SplitN(c.Value, ".", 2)
	if len(parts) != 2 {
		return false
	}
	exp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	mac := hmac.New(sha256.New, sessionSecret)
	mac.Write([]byte(parts[0]))
	want := hex.EncodeToString(mac.Sum(nil))
	return subtle.ConstantTimeCompare([]byte(want), []byte(parts[1])) == 1
}

// ==========================================
// DASHBOARD
// ==========================================
type KeyRow struct {
	Key           string
	Owner         string
	Device        string
	Revoked       bool
	Status        string
	StatusClass   string
	RunsToday     int
	AcctsToday    int
	RunsWeek      int
	AcctsWeek     int
	RunsMonth     int
	AcctsMonth    int
	LastRun       string
	Activated     string
	HasActivation bool
	Limit         *int
	UsedTotal     int
}

// groupThousands renders 1240 as 1,240 for the dashboard.
func groupThousands(n int) string {
	s := strconv.Itoa(n)
	if len(s) <= 3 {
		return s
	}
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return string(out)
}

func humanAgo(t time.Time) string {
	d := time.Since(t)
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	case d < 7*24*time.Hour:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	case d < 30*24*time.Hour:
		return fmt.Sprintf("%dw ago", int(d.Hours()/(24*7)))
	case d < 365*24*time.Hour:
		return fmt.Sprintf("%dmo ago", int(d.Hours()/(24*30)))
	default:
		return fmt.Sprintf("%dy ago", int(d.Hours()/(24*365)))
	}
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	// never let the browser or the CDN serve a cached dashboard: a pushed fix
	// must show up on the next load, not after a hard refresh
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	if !validSession(r) {
		showLoginPage(w, r.URL.Query().Get("error") == "1")
		return
	}

	q := strings.TrimSpace(r.URL.Query().Get("q"))
	filter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("f")))
	switch filter {
	case "used", "unused", "revoked":
	default:
		filter = "all"
	}

	page := 1
	if v, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && v > 0 {
		page = v
	}
	perPage := 50
	like := "%" + q + "%"

	// status filter and search share the same WHERE, so the paging and the
	// counter always agree with what is on screen
	filterSQL := ""
	switch filter {
	case "used":
		filterSQL = " AND (l.device_id IS NOT NULL OR l.activated_at IS NOT NULL) AND COALESCE(l.revoked, false) = false"
	case "unused":
		filterSQL = " AND l.device_id IS NULL AND l.activated_at IS NULL AND COALESCE(l.revoked, false) = false"
	case "revoked":
		filterSQL = " AND COALESCE(l.revoked, false) = true"
	}

	ctx := context.Background()

	// one query gives the counts for all four tabs
	var cAll, cUsed, cUnused, cRevoked int
	if err := db.QueryRow(ctx,
		`SELECT count(*) AS all_keys,
		        count(*) FILTER (WHERE (device_id IS NOT NULL OR activated_at IS NOT NULL) AND COALESCE(revoked, false) = false) AS used_keys,
		        count(*) FILTER (WHERE device_id IS NULL AND activated_at IS NULL AND COALESCE(revoked, false) = false) AS unused_keys,
		        count(*) FILTER (WHERE COALESCE(revoked, false)) AS revoked_keys
		   FROM licenses
		  WHERE $1 = '%%'
		     OR license_key ILIKE $1
		     OR COALESCE(owner_name, '') ILIKE $1
		     OR COALESCE(device_id, '') ILIKE $1`, like).
		Scan(&cAll, &cUsed, &cUnused, &cRevoked); err != nil {
		http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	total := cAll
	switch filter {
	case "used":
		total = cUsed
	case "unused":
		total = cUnused
	case "revoked":
		total = cRevoked
	}

	pages := (total + perPage - 1) / perPage
	if pages < 1 {
		pages = 1
	}
	if page > pages {
		page = pages
	}
	offset := (page - 1) * perPage

	hasUsage := true
	rows, err := db.Query(ctx,
		`SELECT l.license_key,
		        COALESCE(l.owner_name, ''),
		        COALESCE(l.device_id, ''),
		        COALESCE(l.revoked, false),
		        l.activated_at,
		        l.acc_limit,
		        COALESCE(u.d_runs, 0),  COALESCE(u.d_acc, 0),
		        COALESCE(u.w_runs, 0),  COALESCE(u.w_acc, 0),
		        COALESCE(u.m_runs, 0),  COALESCE(u.m_acc, 0),
		        COALESCE(u.total_acc, 0),
		        u.last_run
		   FROM licenses l
		   LEFT JOIN (
		        SELECT license_key,
		               COUNT(*)      FILTER (WHERE at >= now() - interval '24 hours') AS d_runs,
		               SUM(accounts) FILTER (WHERE at >= now() - interval '24 hours') AS d_acc,
		               COUNT(*)      FILTER (WHERE at >= now() - interval '7 days')   AS w_runs,
		               SUM(accounts) FILTER (WHERE at >= now() - interval '7 days')   AS w_acc,
		               COUNT(*)      FILTER (WHERE at >= now() - interval '30 days')  AS m_runs,
		               SUM(accounts) FILTER (WHERE at >= now() - interval '30 days')  AS m_acc,
		               SUM(accounts) AS total_acc,
		               MAX(at) AS last_run
		          FROM runs
		         GROUP BY license_key
		   ) u ON u.license_key = l.license_key
		  WHERE ($1 = '%%'
		     OR l.license_key ILIKE $1
		     OR COALESCE(l.owner_name, '') ILIKE $1
		     OR COALESCE(l.device_id, '') ILIKE $1)`+filterSQL+`
		  ORDER BY COALESCE(l.revoked, false) ASC,
		           COALESCE(u.m_acc, 0) DESC,
		           COALESCE(u.m_runs, 0) DESC,
		           COALESCE(u.w_acc, 0) DESC,
		           COALESCE(u.w_runs, 0) DESC,
		           COALESCE(l.owner_name, 'zzzz') ASC,
		           l.license_key ASC
		  LIMIT $2 OFFSET $3`, like, perPage, offset)
	if err != nil {
		// fall back, but leave a trail: a schema drift must not look like an empty table
		log.Printf("dashboard: usage query failed, falling back: %v", err)
		hasUsage = false
		rows, err = db.Query(ctx,
			`SELECT license_key,
			        COALESCE(owner_name, ''),
			        COALESCE(device_id, ''),
			        COALESCE(revoked, false),
			        activated_at,
			        acc_limit
			   FROM licenses l
			  WHERE ($1 = '%%'
			     OR l.license_key ILIKE $1
			     OR COALESCE(l.owner_name, '') ILIKE $1
			     OR COALESCE(l.device_id, '') ILIKE $1)`+filterSQL+`
			  ORDER BY COALESCE(l.revoked, false) ASC,
			           COALESCE(l.owner_name, 'zzzz') ASC,
			           l.license_key ASC
			  LIMIT $2 OFFSET $3`, like, perPage, offset)
	}
	if err != nil {
		http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var keys []KeyRow
	for rows.Next() {
		var k KeyRow
		var last *time.Time
		var activated *time.Time
		var accLimit *int
		var scanErr error
		if hasUsage {
			scanErr = rows.Scan(&k.Key, &k.Owner, &k.Device, &k.Revoked,
				&activated, &accLimit,
				&k.RunsToday, &k.AcctsToday,
				&k.RunsWeek, &k.AcctsWeek,
				&k.RunsMonth, &k.AcctsMonth,
				&k.UsedTotal, &last)
		} else {
			scanErr = rows.Scan(&k.Key, &k.Owner, &k.Device, &k.Revoked, &activated, &accLimit)
		}
		if scanErr != nil {
			// a column mismatch used to hide rows without a trace - log it instead
			log.Printf("scan failed for %s: %v", k.Key, scanErr)
			continue
		}
		if last != nil {
			k.LastRun = humanAgo(*last)
		}
		if activated != nil {
			k.Activated = humanAgo(*activated)
			k.HasActivation = true
		}
		k.Limit = accLimit
		switch {
		case k.Revoked:
			k.Status, k.StatusClass = "Revoked", "revoked"
		case k.Device != "":
			k.Status, k.StatusClass = "Used", "used"
		default:
			// no device means the key is still free, whatever old timestamp it
			// may carry - a real activation always writes the device too
			k.Status, k.StatusClass = "Available", "avail"
		}
		keys = append(keys, k)
	}

	data := struct {
		Rows         []KeyRow
		Flash        string
		HasUsage     bool
		Q            string
		Filter       string
		Page         int
		Pages        int
		Total        int
		PerPage      int
		Prev         int
		Next         int
		HasPrev      bool
		HasNext      bool
		AllCount     int
		UsedCount    int
		UnusedCount  int
		RevokedCount int
	}{
		Rows:         keys,
		Flash:        r.URL.Query().Get("msg"),
		HasUsage:     hasUsage,
		Q:            q,
		Filter:       filter,
		Page:         page,
		Pages:        pages,
		Total:        total,
		PerPage:      perPage,
		Prev:         page - 1,
		Next:         page + 1,
		HasPrev:      page > 1,
		HasNext:      page < pages,
		AllCount:     cAll,
		UsedCount:    cUsed,
		UnusedCount:  cUnused,
		RevokedCount: cRevoked,
	}

	funcs := template.FuncMap{"n": groupThousands, "u": url.QueryEscape}
	tmpl := template.Must(template.New("dash").Funcs(funcs).Parse(dashboardHTML))
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("template: %v", err)
	}
}

const dashboardHTML = `<html>
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>License Dashboard</title>
	<style>
		* { box-sizing: border-box; }
		body { font-family: system-ui, -apple-system, sans-serif; padding: 16px; background: #f4f4f9; margin: 0; }
		h2 { margin: 0 0 12px; font-size: 20px; }
		.topbar { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 12px; }
		table { border-collapse: collapse; width: 100%; background: white; box-shadow: 0 1px 3px rgba(0,0,0,.08); border-radius: 8px; overflow: hidden; }
		th, td { padding: 8px 10px; border-bottom: 1px solid #ececf1; text-align: left; vertical-align: middle; font-size: 13px; }
		th { background: #2b2b33; color: white; font-size: 11.5px; letter-spacing: .4px; text-transform: uppercase; }
		tr:last-child td { border-bottom: 0; }
		.avail { color: #0a7d33; font-weight: 600; }
		.used { color: #b3261e; font-weight: 600; }
		.revoked { color: #6b6b75; font-weight: 700; }
		.badge::before { content: ''; display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: currentColor; margin-right: 6px; vertical-align: middle; }
		.dev { color: #8a8a94; font-size: 11px; margin-top: 2px; }
		.u { font-size: 12.5px; line-height: 1.55; white-space: nowrap; }
		.uk { display: inline-block; width: 44px; color: #9a9aa4; font-size: 10px; text-transform: uppercase; letter-spacing: .5px; }
		input[type=text], input[type=number] { padding: 6px 8px; border: 1px solid #d5d5dd; border-radius: 5px; font-size: 13px; }
		.namebox { width: 100%; }
		.credbox { width: 100%; }
		td[data-label="User"] form.setname, td[data-label="User"] form.creditsrow { display: flex !important; gap: 4px; align-items: center; }
		td[data-label="User"] form.setname .save, td[data-label="User"] form.creditsrow .save { flex: 0 0 auto; }
		form.creditsrow { margin-top: 4px; }
		td[data-label="User"] .dev { margin-top: 3px; font-size: 10.5px; }
		.search { width: 240px; }
		.pageno { width: 62px; }
		button { padding: 6px 11px; border: 0; border-radius: 5px; cursor: pointer; font-size: 12.5px; }
		.save { background: #2b2b33; color: #fff; }
		.revoke { background: #b3261e; color: #fff; }
		.del { background: #55555f; color: #fff; margin-left: 6px; }
		.del:hover { background: #33333b; }
		.restore { background: #0a7d33; color: #fff; }
		.logout { background: #2b2b33; color: #fff; padding: 8px 14px; }
		.flash { background: #e8f5e9; border: 1px solid #a5d6a7; color: #1b5e20; padding: 9px 12px; margin-bottom: 12px; border-radius: 6px; font-size: 13px; }
		form.inline { display: inline; margin: 0; }
		td.mono { font-family: ui-monospace, Consolas, monospace; font-size: 12.5px; }

		.toolbar { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 12px; }
		.pager { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin: 12px 0; font-size: 13px; }
		.filters { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 12px; }
		.filters .f { padding: 6px 12px; border: 1px solid #d5d5dd; border-radius: 6px; background: #fff; color: #2b2b33; text-decoration: none; font-size: 13px; }
		.filters .f span { color: #9a9aa4; font-size: 11.5px; margin-left: 4px; }
		.filters .f.on { background: #2b2b33; color: #fff; border-color: #2b2b33; }
		.filters .f.on span { color: #c9c9d2; }
		.pager a, .pager .off { padding: 6px 12px; border-radius: 6px; border: 1px solid #d5d5dd; background: #fff; color: #2b2b33; text-decoration: none; }
		.pager a:hover { background: #ececf1; }
		.pager .off { color: #b9b9c2; background: #f7f7fa; }
		.pager .count { color: #6b6b75; }
		.pager form { display: inline-flex; gap: 6px; align-items: center; margin: 0; }

		.u3 { display: block; }
		.u3 .cell { display: block; font-size: 12.5px; line-height: 1.55; white-space: nowrap; }
		.u3 .v { color: #2b2b33; }

		/* ---------- phone layout: compact card, 3 columns of usage ---------- */
		@media (max-width: 820px) {
			body { padding: 8px; }
			h2 { font-size: 17px; }
			.topbar { margin-bottom: 6px; }
			.toolbar { gap: 6px; margin-bottom: 8px; }
			.filters { gap: 6px; margin-bottom: 8px; }
			.filters .f { padding: 5px 10px; font-size: 12.5px; }
			.search { width: 100%; }
			table, tbody, tr, td { display: block; width: 100%; }
			table { box-shadow: none; background: transparent; border-radius: 0; }
			thead, tr:first-child { display: none; }

			tr {
				display: grid;
				grid-template-columns: 1fr auto;
				column-gap: 8px;
				background: #fff; border: 1px solid #e4e4ea; border-radius: 8px;
				margin-bottom: 8px; padding: 8px 10px 9px;
				box-shadow: 0 1px 2px rgba(0,0,0,.05);
			}
			td { border: 0; padding: 0; font-size: 13px; }
			td::before { display: none; }

			/* 1: name + save */
			td[data-label="User"] { grid-column: 1 / 3; }
			td[data-label="User"] form { display: flex; gap: 6px; }
			.namebox { width: 100%; padding: 6px 9px; font-size: 13.5px; }
			td[data-label="User"] .save { padding: 6px 13px; }

			/* 2: key */
			td.mono { grid-column: 1 / 3; font-size: 11.5px; line-height: 1.25; color: #4a4a55; margin-top: 2px; word-break: break-all; }

			/* 3: status + last run, revoke on the right */
			td[data-label="Status"] { grid-column: 1; margin-top: 3px; }
			td[data-label="Status"] .badge { font-size: 12.5px; }
			td[data-label="Status"] .run { font-size: 10.5px; }
			td[data-label="Status"] .guid { font-size: 9.5px; line-height: 1.2; margin-top: 1px; max-width: 100%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
			td[data-label="Action"] { grid-column: 2; grid-row: 3; align-self: start; justify-self: end; margin-top: 3px; }
			td[data-label="Action"] form { display: block; margin-top: 4px; }
			td[data-label="Action"] .revoke,
			td[data-label="Action"] .restore,
			td[data-label="Action"] .del { padding: 4px 10px; font-size: 11.5px; margin: 0; }

			/* 4: 24H / 7D / 30D on one row */
			td[data-label="Usage"] { grid-column: 1 / 3; margin-top: 7px; padding-top: 7px; border-top: 1px solid #f0f0f4; }
			td[data-label="Usage"] .u3 { display: block; }
			td[data-label="Usage"] .u3 .cell { display: flex; align-items: baseline; gap: 6px; white-space: nowrap; line-height: 1.45; }
			td[data-label="Usage"] .u3 .uk { width: 30px; font-size: 9.5px; flex: 0 0 30px; }
			td[data-label="Usage"] .u3 .v { font-size: 11.5px; }

			.pager { justify-content: center; gap: 6px; margin: 8px 0; }
			.pager a, .pager .off { padding: 5px 10px; }
		}
	</style>
</head>
<body>
	<div class="topbar">
		<h2>License Keys</h2>
		<form action="/logout" method="POST"><button class="logout" type="submit">Logout</button></form>
	</div>
	{{if .Flash}}<div class="flash">{{.Flash}}</div>{{end}}

	<form method="GET" action="/" class="toolbar">
		<input class="search" type="text" name="q" value="{{.Q}}" placeholder="Search user, key or device...">
		<button class="save" type="submit">Search</button>
		{{if .Q}}<a href="/" style="font-size:13px;color:#b3261e;text-decoration:none;">clear</a>{{end}}
		<span class="count" style="color:#6b6b75;font-size:12.5px;">{{.Total}} key{{if ne .Total 1}}s{{end}}{{if .Q}} matching &#8220;{{.Q}}&#8221;{{end}} &#183; ranked by accounts this month</span>
	</form>

	<div class="filters">
		<a class="f{{if eq .Filter "all"}} on{{end}}" href="/?f=all&q={{u .Q}}">All <span>{{.AllCount}}</span></a>
		<a class="f{{if eq .Filter "used"}} on{{end}}" href="/?f=used&q={{u .Q}}">Used <span>{{.UsedCount}}</span></a>
		<a class="f{{if eq .Filter "unused"}} on{{end}}" href="/?f=unused&q={{u .Q}}">Unused <span>{{.UnusedCount}}</span></a>
		<a class="f{{if eq .Filter "revoked"}} on{{end}}" href="/?f=revoked&q={{u .Q}}">Revoked <span>{{.RevokedCount}}</span></a>
	</div>

	<div class="pager">
		{{if .HasPrev}}<a href="/?f={{.Filter}}&q={{u .Q}}&page={{.Prev}}">&#171; Back</a>{{else}}<span class="off">&#171; Back</span>{{end}}
		<span class="count">Page {{.Page}} of {{.Pages}}</span>
		{{if .HasNext}}<a href="/?f={{.Filter}}&q={{u .Q}}&page={{.Next}}">Next &#187;</a>{{else}}<span class="off">Next &#187;</span>{{end}}
		<form method="GET" action="/">
			<input type="hidden" name="q" value="{{.Q}}">
			<input type="hidden" name="f" value="{{.Filter}}">
			<input class="pageno" type="number" name="page" min="1" max="{{.Pages}}" value="{{.Page}}" aria-label="page">
			<button class="save" type="submit">Go</button>
		</form>
	</div>

	<table id="keyTable">
		<tr><th style="width:23%">User</th><th style="width:21%">License Key</th><th style="width:18%">Status</th>{{if .HasUsage}}<th style="width:26%">Usage</th>{{end}}<th style="width:12%">Action</th></tr>
		{{range .Rows}}
		<tr>
			<td data-label="User">
				<form class="inline setname" action="/set-name" method="POST">
					<input type="hidden" name="key" value="{{.Key}}">
					<input class="namebox" type="text" name="name" value="{{.Owner}}" placeholder="who is this?">
					<button class="save" type="submit">Save</button>
				</form>
				<form class="inline creditsrow" action="/set-credits" method="POST">
					<input type="hidden" name="key" value="{{.Key}}">
					<input type="hidden" name="page" value="{{$.Page}}">
					<input type="hidden" name="q" value="{{$.Q}}">
					<input type="hidden" name="f" value="{{$.Filter}}">
					<input class="credbox" type="number" min="0" name="limit" value="{{if .Limit}}{{.Limit}}{{end}}" placeholder="unlimited">
					<button class="save" type="submit">Save</button>
				</form>
				<div class="dev">{{n .UsedTotal}} acc used{{if .Limit}} / {{n .Limit}}{{end}}</div>
			</td>
			<td class="mono" data-label="Key">{{.Key}}</td>
			<td data-label="Status">
				<span class="badge {{.StatusClass}}">{{.Status}}</span>{{if .LastRun}}<span class="dev run"> &#183; {{.LastRun}}</span>{{end}}
				{{if .Device}}<div class="dev guid" title="{{.Device}}">{{if .Activated}}{{.Activated}} &#183; {{end}}{{.Device}}</div>{{end}}
				{{if .Activated}}{{if not .Device}}<div class="dev">old attempt {{.Activated}} &#8212; no device recorded</div>{{end}}{{end}}
			</td>
			{{if $.HasUsage}}
						<td data-label="Usage">
				<div class="u3">
					<div class="cell"><span class="uk">24H</span><span class="v">{{if .RunsToday}}{{.RunsToday}} run{{if ne .RunsToday 1}}s{{end}} &#183; {{n .AcctsToday}} acc{{else}}&#8212;{{end}}</span></div>
					<div class="cell"><span class="uk">7D</span><span class="v">{{if .RunsWeek}}{{.RunsWeek}} runs &#183; {{n .AcctsWeek}} acc{{else}}&#8212;{{end}}</span></div>
					<div class="cell"><span class="uk">30D</span><span class="v">{{if .RunsMonth}}{{.RunsMonth}} runs &#183; {{n .AcctsMonth}} acc{{else}}&#8212;{{end}}</span></div>
				</div>
			</td>
			{{end}}
			<td data-label="Action">
				{{if .Revoked}}
					<form class="inline" action="/restore" method="POST">
						<input type="hidden" name="key" value="{{.Key}}">
						<input type="hidden" name="page" value="{{$.Page}}">
						<input type="hidden" name="q" value="{{$.Q}}">
						<input type="hidden" name="f" value="{{$.Filter}}">
						<button class="restore" type="submit">Restore</button>
					</form>
				{{else}}
					<form class="inline" action="/revoke" method="POST">
						<input type="hidden" name="key" value="{{.Key}}">
						<input type="hidden" name="page" value="{{$.Page}}">
						<input type="hidden" name="q" value="{{$.Q}}">
						<input type="hidden" name="f" value="{{$.Filter}}">
						<button class="revoke" type="submit">Revoke</button>
					</form>
				{{end}}
				<form class="inline" action="/delete" method="POST"
				      onsubmit="return confirm('DELETE THIS KEY PERMANENTLY?\n\n{{.Key}}\n\nIt will never work again and cannot be undone.');">
					<input type="hidden" name="key" value="{{.Key}}">
					<input type="hidden" name="page" value="{{$.Page}}">
					<input type="hidden" name="q" value="{{$.Q}}">
					<input type="hidden" name="f" value="{{$.Filter}}">
					<button class="del" type="submit">Delete</button>
				</form>
			</td>
		</tr>
		{{end}}
	</table>

	<div class="pager">
		{{if .HasPrev}}<a href="/?f={{.Filter}}&q={{u .Q}}&page={{.Prev}}">&#171; Back</a>{{else}}<span class="off">&#171; Back</span>{{end}}
		<span class="count">Page {{.Page}} of {{.Pages}} &#183; {{.Total}} key{{if ne .Total 1}}s{{end}}</span>
		{{if .HasNext}}<a href="/?f={{.Filter}}&q={{u .Q}}&page={{.Next}}">Next &#187;</a>{{else}}<span class="off">Next &#187;</span>{{end}}
	</div>

	<script>
		// Save a name without reloading the page. A normal form POST reloads the
		// table and throws you back to the top of the list.
		document.addEventListener('submit', function (e) {
			var f = e.target;
			if (!f || !f.classList || !f.classList.contains('setname')) return;
			e.preventDefault();

			var btn = f.querySelector('button');
			var label = btn.textContent;
			btn.disabled = true;
			btn.textContent = '...';

			fetch(f.action, { method: 'POST', body: new FormData(f), credentials: 'same-origin', headers: { 'X-Requested-With': 'fetch' } })
				.then(function (resp) {
					if (resp.status === 401) {
						btn.textContent = 'Login';
						setTimeout(function () { window.location.href = '/'; }, 900);
						return;
					}
					if (!resp.ok && resp.status !== 204) throw new Error('http ' + resp.status);
					btn.textContent = 'Saved';
					setTimeout(function () { btn.textContent = label; btn.disabled = false; }, 1200);
				})
				.catch(function () {
					btn.textContent = 'Retry';
					btn.disabled = false;
				});
		});
	</script>
</body>
</html>
`

// ==========================================
// LOGIN / LOGOUT
// ==========================================
func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.FormValue("password")), []byte(adminPassword)) == 1 {
		http.SetCookie(w, &http.Cookie{
			Name:     "admin_session",
			Value:    makeSession(),
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
			MaxAge:   sessionHours * 3600,
		})
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?error=1", http.StatusSeeOther)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "admin_session", Value: "", Path: "/", HttpOnly: true, MaxAge: -1})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func showLoginPage(w http.ResponseWriter, hasError bool) {
	errMsg := ""
	if hasError {
		errMsg = `<p style="color:#b3261e;">Incorrect password. Try again.</p>`
	}
	tmpl := template.Must(template.New("login").Parse(`
	<html><head><meta charset="utf-8"><title>Admin Login</title>
	<style>
		body { font-family: system-ui, sans-serif; display:flex; justify-content:center; align-items:center; height:100vh; background:#f4f4f9; margin:0; }
		.box { background:#fff; padding:40px; border-radius:8px; box-shadow:0 4px 14px rgba(0,0,0,.1); text-align:center; }
		input { padding:10px; width:250px; margin:10px 0; border:1px solid #ccc; border-radius:4px; }
		button { padding:10px 20px; background:#2b2b33; color:#fff; border:0; border-radius:4px; cursor:pointer; width:272px; }
	</style></head><body>
	<div class="box"><h2>Admin Access</h2>` + errMsg + `
	<form action="/login" method="POST">
		<input type="password" name="password" placeholder="Admin password" required><br>
		<button type="submit">Login</button>
	</form></div></body></html>`))
	tmpl.Execute(w, nil)
}

// ==========================================
// ADMIN ACTIONS
// ==========================================
func requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	if !validSession(r) {
		// an ajax caller must not be handed the login page with a 200 - it would
		// look like the save worked
		if r.Header.Get("X-Requested-With") == "fetch" {
			w.WriteHeader(http.StatusUnauthorized)
			return false
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return false
	}
	return true
}

// backTo builds the dashboard URL to return to after an action, keeping the
// search and the page the user was on.
func backTo(r *http.Request, msg string) string {
	q := strings.TrimSpace(r.FormValue("q"))
	page := strings.TrimSpace(r.FormValue("page"))
	v := url.Values{}
	if q != "" {
		v.Set("q", q)
	}
	if page != "" && page != "1" && page != "0" {
		v.Set("page", page)
	}
	if msg != "" {
		v.Set("msg", msg)
	}
	if len(v) == 0 {
		return "/"
	}
	return "/?" + v.Encode()
}

func handleSetName(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	key := strings.TrimSpace(r.FormValue("key"))
	name := strings.TrimSpace(r.FormValue("name"))
	if key == "" {
		http.Redirect(w, r, "/?msg=Missing+key", http.StatusSeeOther)
		return
	}
	if _, err := db.Exec(context.Background(),
		`UPDATE licenses SET owner_name = NULLIF($1, '') WHERE license_key = $2`, name, key); err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	// Saved from the page itself: no redirect, no reload, no re-download of
	// the whole table. The button confirms in place.
	if r.Header.Get("X-Requested-With") == "fetch" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	msg := "Name saved"
	if name == "" {
		msg = "Name cleared"
	}
	http.Redirect(w, r, backTo(r, msg), http.StatusSeeOther)
}

func handleRevoke(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	key := strings.TrimSpace(r.FormValue("key"))
	if key == "" {
		http.Redirect(w, r, "/?msg=Missing+key", http.StatusSeeOther)
		return
	}
	// keep the device id: the record of who had it is useful after revocation
	_, err := db.Exec(context.Background(),
		`UPDATE licenses SET revoked = true, revoked_at = NOW() WHERE license_key = $1`, key)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, backTo(r, "Key revoked - the bot will refuse to run"), http.StatusSeeOther)
}

func handleRestore(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	key := strings.TrimSpace(r.FormValue("key"))
	if key == "" {
		http.Redirect(w, r, "/?msg=Missing+key", http.StatusSeeOther)
		return
	}
	_, err := db.Exec(context.Background(),
		`UPDATE licenses SET revoked = false, revoked_at = NULL WHERE license_key = $1`, key)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, backTo(r, "Key restored"), http.StatusSeeOther)
}

// ==========================================
// BOT API: activate + verify
// ==========================================
func writeJSON(w http.ResponseWriter, code int, v ActivationResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// handleDeleteKey removes the key for good: the licence, its history and its
// usage rows. The row is gone, so /activate can never match it again.
func handleDeleteKey(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	key := strings.TrimSpace(r.FormValue("key"))
	if key == "" {
		http.Redirect(w, r, "/?msg=Missing+key", http.StatusSeeOther)
		return
	}

	ctx := context.Background()

	// all three deletes or none: a half-finished delete would leave history
	// without its key, or a key without its history
	tx, err := db.Begin(ctx)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(ctx)

	_, _ = tx.Exec(ctx, `DELETE FROM runs WHERE license_key = $1`, key)
	_, _ = tx.Exec(ctx, `DELETE FROM usage WHERE license_key = $1`, key)

	res, err := tx.Exec(ctx, `DELETE FROM licenses WHERE license_key = $1`, key)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	if res.RowsAffected() == 0 {
		http.Redirect(w, r, backTo(r, "Key not found"), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, backTo(r, "Key deleted permanently"), http.StatusSeeOther)
}
func handleActivate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ActivationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Key) == "" || strings.TrimSpace(req.DeviceID) == "" {
		writeJSON(w, http.StatusBadRequest, ActivationResponse{Status: "invalid", Error: "key and device_id are required"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var existingDevice *string
	var revoked bool
	err := db.QueryRow(ctx,
		`SELECT device_id, COALESCE(revoked, false) FROM licenses WHERE license_key = $1`, req.Key).
		Scan(&existingDevice, &revoked)

	if err != nil {
		if err == pgx.ErrNoRows {
			writeJSON(w, http.StatusForbidden, ActivationResponse{Status: "invalid", Error: "Invalid license key."})
			return
		}
		writeJSON(w, http.StatusInternalServerError, ActivationResponse{Status: "error", Error: "Database error"})
		return
	}

	// revoked keys never activate, on any machine
	if revoked {
		writeJSON(w, http.StatusForbidden, ActivationResponse{Status: "revoked", Error: "This license has been revoked."})
		return
	}

	if existingDevice == nil {
		if _, err := db.Exec(ctx,
			`UPDATE licenses SET device_id = $1, activated_at = NOW() WHERE license_key = $2`,
			req.DeviceID, req.Key); err != nil {
			writeJSON(w, http.StatusInternalServerError, ActivationResponse{Status: "error", Error: "Database error"})
			return
		}
		writeJSON(w, http.StatusOK, ActivationResponse{Status: "activated", Token: generateToken(req.DeviceID)})
		return
	}

	if *existingDevice == req.DeviceID {
		writeJSON(w, http.StatusOK, ActivationResponse{Status: "activated", Token: generateToken(req.DeviceID)})
		return
	}

	writeJSON(w, http.StatusConflict, ActivationResponse{Status: "used", Error: "This key is already activated on another machine."})
}

// handleVerify is what makes revocation real: the bot calls this on every start
// (and ideally every few hours). Revoked -> the bot must refuse to run.
func handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ActivationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var existingDevice *string
	var revoked bool
	err := db.QueryRow(ctx,
		`SELECT device_id, COALESCE(revoked, false) FROM licenses WHERE license_key = $1`, req.Key).
		Scan(&existingDevice, &revoked)

	if err != nil {
		if err == pgx.ErrNoRows {
			writeJSON(w, http.StatusForbidden, ActivationResponse{Status: "invalid", Error: "Invalid license key."})
			return
		}
		writeJSON(w, http.StatusInternalServerError, ActivationResponse{Status: "error", Error: "Database error"})
		return
	}

	if revoked {
		writeJSON(w, http.StatusForbidden, ActivationResponse{Status: "revoked", Error: "This license has been revoked."})
		return
	}
	if existingDevice == nil {
		writeJSON(w, http.StatusForbidden, ActivationResponse{Status: "not_activated", Error: "This key has not been activated yet."})
		return
	}
	if *existingDevice != req.DeviceID {
		writeJSON(w, http.StatusConflict, ActivationResponse{Status: "used", Error: "This key belongs to another machine."})
		return
	}
	if subtle.ConstantTimeCompare([]byte(req.Token), []byte(generateToken(*existingDevice))) != 1 {
		writeJSON(w, http.StatusForbidden, ActivationResponse{Status: "invalid", Error: "Bad token."})
		return
	}

	writeJSON(w, http.StatusOK, ActivationResponse{Status: "ok"})
}

// handleUsage is called ONCE per run, when the user presses Enter with the Excel loaded.
// It records how many accounts were loaded. Same auth as /verify, so only the machine
// that owns the key can write to that key's profile.
// handleQuota tells the bot how many accounts the key has used and how many it
// is allowed. Called at startup, before the menu, so an exhausted key stops there.
func handleQuota(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Key      string `json:"key"`
		DeviceID string `json:"device_id"`
		Token    string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if req.Key == "" || req.DeviceID == "" {
		writeJSON(w, http.StatusBadRequest, ActivationResponse{Status: "invalid", Error: "key and device_id are required"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var device *string
	var revoked bool
	var limit *int
	if err := db.QueryRow(ctx,
		`SELECT device_id, COALESCE(revoked, false), acc_limit FROM licenses WHERE license_key = $1`, req.Key).
		Scan(&device, &revoked, &limit); err != nil {
		writeJSON(w, http.StatusForbidden, ActivationResponse{Status: "invalid", Error: "Invalid license key."})
		return
	}
	if revoked {
		writeJSON(w, http.StatusForbidden, ActivationResponse{Status: "revoked"})
		return
	}
	if device == nil || *device != req.DeviceID {
		writeJSON(w, http.StatusConflict, ActivationResponse{Status: "used"})
		return
	}
	if subtle.ConstantTimeCompare([]byte(req.Token), []byte(generateToken(*device))) != 1 {
		writeJSON(w, http.StatusForbidden, ActivationResponse{Status: "invalid"})
		return
	}

	var used int
	_ = db.QueryRow(ctx, `SELECT COALESCE(SUM(accounts), 0) FROM runs WHERE license_key = $1`, req.Key).Scan(&used)

	lim := 0
	if limit != nil {
		lim = *limit
	}
	writeJSON(w, http.StatusOK, ActivationResponse{Status: "ok", Used: used, Limit: lim})
}

// handleSetCredits stores the allowance. Empty input means unlimited.
func handleSetCredits(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	key := strings.TrimSpace(r.FormValue("key"))
	if key == "" {
		http.Redirect(w, r, "/?msg=Missing+key", http.StatusSeeOther)
		return
	}
	raw := strings.TrimSpace(r.FormValue("limit"))

	if raw == "" {
		if _, err := db.Exec(context.Background(),
			`UPDATE licenses SET acc_limit = NULL WHERE license_key = $1`, key); err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, backTo(r, "Credits removed - unlimited"), http.StatusSeeOther)
		return
	}

	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		http.Redirect(w, r, backTo(r, "Credits must be a number"), http.StatusSeeOther)
		return
	}
	// zero means unlimited, the same as an empty box - store it that way so the
	// panel shows "unlimited" instead of a confusing "/ 0"
	if n == 0 {
		if _, err := db.Exec(context.Background(),
			`UPDATE licenses SET acc_limit = NULL WHERE license_key = $1`, key); err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, backTo(r, "Credits removed - unlimited"), http.StatusSeeOther)
		return
	}
	if _, err := db.Exec(context.Background(),
		`UPDATE licenses SET acc_limit = $1 WHERE license_key = $2`, n, key); err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, backTo(r, "Credits updated"), http.StatusSeeOther)
}

func handleUsage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Key      string `json:"key"`
		DeviceID string `json:"device_id"`
		Token    string `json:"token"`
		Accounts int    `json:"accounts"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if req.Key == "" || req.DeviceID == "" {
		writeJSON(w, http.StatusBadRequest, ActivationResponse{Status: "invalid", Error: "key and device_id are required"})
		return
	}
	if req.Accounts < 0 {
		req.Accounts = 0
	}
	if req.Accounts > 100000 {
		req.Accounts = 100000
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var existingDevice *string
	var revoked bool
	err := db.QueryRow(ctx,
		`SELECT device_id, COALESCE(revoked, false) FROM licenses WHERE license_key = $1`, req.Key).
		Scan(&existingDevice, &revoked)
	if err != nil {
		if err == pgx.ErrNoRows {
			writeJSON(w, http.StatusForbidden, ActivationResponse{Status: "invalid", Error: "Invalid license key."})
			return
		}
		writeJSON(w, http.StatusInternalServerError, ActivationResponse{Status: "error", Error: "Database error"})
		return
	}
	if revoked {
		writeJSON(w, http.StatusForbidden, ActivationResponse{Status: "revoked", Error: "This license has been revoked."})
		return
	}
	if existingDevice == nil || *existingDevice != req.DeviceID {
		writeJSON(w, http.StatusConflict, ActivationResponse{Status: "used", Error: "This key belongs to another machine."})
		return
	}
	if subtle.ConstantTimeCompare([]byte(req.Token), []byte(generateToken(*existingDevice))) != 1 {
		writeJSON(w, http.StatusForbidden, ActivationResponse{Status: "invalid", Error: "Bad token."})
		return
	}

	// credits: refuse the run outright when it would pass the allowance
	var accLimit *int
	_ = db.QueryRow(ctx, `SELECT acc_limit FROM licenses WHERE license_key = $1`, req.Key).Scan(&accLimit)
	if accLimit != nil && *accLimit > 0 {
		var used int
		_ = db.QueryRow(ctx, `SELECT COALESCE(SUM(accounts), 0) FROM runs WHERE license_key = $1`, req.Key).Scan(&used)
		if used+req.Accounts > *accLimit {
			writeJSON(w, http.StatusPaymentRequired, ActivationResponse{
				Status: "limit", Used: used, Limit: *accLimit, Error: "Account limit reached.",
			})
			return
		}
	}

	// one row per run, with a real timestamp - this is what the rolling
	// 24h / 7d / 30d windows read
	if _, err := db.Exec(ctx,
		`INSERT INTO runs (license_key, at, accounts) VALUES ($1, NOW(), $2)`,
		req.Key, req.Accounts); err != nil {
		writeJSON(w, http.StatusInternalServerError, ActivationResponse{Status: "error", Error: "runs table missing? Run runs.sql."})
		return
	}

	// keep the daily table too, so history and any old query keep working
	_, err = db.Exec(ctx,
		`INSERT INTO usage (license_key, day, runs, accounts)
		 VALUES ($1, (now() AT TIME ZONE 'Africa/Nairobi')::date, 1, $2)
		 ON CONFLICT (license_key, day) DO UPDATE
		    SET runs        = usage.runs + 1,
		        accounts    = usage.accounts + EXCLUDED.accounts,
		        last_run_at = NOW()`, req.Key, req.Accounts)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, ActivationResponse{Status: "error", Error: "Usage table missing? Run the SQL."})
		return
	}

	writeJSON(w, http.StatusOK, ActivationResponse{Status: "ok"})
}
