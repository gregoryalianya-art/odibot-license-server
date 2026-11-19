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
	db, err = pgxpool.New(context.Background(), dbURL)
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
	http.HandleFunc("/activate", handleActivate)
	http.HandleFunc("/verify", handleVerify)

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
	Key         string
	Owner       string
	Device      string
	Revoked     bool
	Status      string
	StatusClass string
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	if !validSession(r) {
		showLoginPage(w, r.URL.Query().Get("error") == "1")
		return
	}

	rows, err := db.Query(context.Background(),
		`SELECT license_key,
		        COALESCE(owner_name, ''),
		        COALESCE(device_id, ''),
		        COALESCE(revoked, false)
		   FROM licenses
		  ORDER BY COALESCE(revoked, false) ASC,
		           COALESCE(owner_name, 'zzzz') ASC,
		           license_key ASC`)
	if err != nil {
		http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var keys []KeyRow
	for rows.Next() {
		var k KeyRow
		if err := rows.Scan(&k.Key, &k.Owner, &k.Device, &k.Revoked); err != nil {
			continue
		}
		switch {
		case k.Revoked:
			k.Status, k.StatusClass = "⛔ Revoked", "revoked"
		case k.Device != "":
			k.Status, k.StatusClass = "🔴 Used", "used"
		default:
			k.Status, k.StatusClass = "🟢 Available", "avail"
		}
		keys = append(keys, k)
	}

	data := struct {
		Rows  []KeyRow
		Flash string
	}{Rows: keys, Flash: r.URL.Query().Get("msg")}

	tmpl := template.Must(template.New("dash").Parse(dashboardHTML))
	tmpl.Execute(w, data)
}

const dashboardHTML = `
<html>
<head>
	<meta charset="utf-8">
	<title>License Dashboard</title>
	<style>
		body { font-family: system-ui, sans-serif; padding: 20px; background: #f4f4f9; margin: 0; }
		h2 { margin-top: 0; }
		table { border-collapse: collapse; width: 100%; background: white; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
		th, td { padding: 10px 12px; border: 1px solid #e2e2e8; text-align: left; vertical-align: middle; }
		th { background: #2b2b33; color: white; font-size: 13px; letter-spacing: .3px; }
		.avail { color: #0a7d33; font-weight: 600; }
		.used { color: #b3261e; font-weight: 600; }
		.revoked { color: #6b6b75; font-weight: 700; }
		.dev { color: #777; font-size: 12px; }
		input[type=text] { padding: 6px 8px; border: 1px solid #ccc; border-radius: 4px; font-size: 13px; }
		.namebox { width: 150px; }
		.search { width: 280px; margin-bottom: 14px; }
		button { padding: 6px 12px; border: 0; border-radius: 4px; cursor: pointer; font-size: 13px; }
		.save { background: #2b2b33; color: #fff; }
		.revoke { background: #b3261e; color: #fff; }
		.restore { background: #0a7d33; color: #fff; }
		.logout { background: #2b2b33; color: #fff; float: right; padding: 9px 18px; }
		.flash { background: #e8f5e9; border: 1px solid #a5d6a7; color: #1b5e20; padding: 10px 14px; margin-bottom: 14px; border-radius: 4px; }
		form.inline { display: inline; margin: 0; }
		td.mono { font-family: ui-monospace, Consolas, monospace; font-size: 13px; }
	</style>
</head>
<body>
	<form action="/logout" method="POST"><button class="logout" type="submit">Logout</button></form>
	<h2>License Keys</h2>
	{{if .Flash}}<div class="flash">{{.Flash}}</div>{{end}}
	<input class="search" type="text" id="search" onkeyup="filterTable()" placeholder="Search user, key or device...">
	<table id="keyTable">
		<tr><th style="width:22%">User</th><th style="width:30%">License Key</th><th style="width:26%">Status</th><th style="width:22%">Action</th></tr>
		{{range .Rows}}
		<tr>
			<td>
				<form class="inline" action="/set-name" method="POST">
					<input type="hidden" name="key" value="{{.Key}}">
					<input class="namebox" type="text" name="name" value="{{.Owner}}" placeholder="who is this?">
					<button class="save" type="submit">Save</button>
				</form>
			</td>
			<td class="mono">{{.Key}}</td>
			<td>
				<span class="{{.StatusClass}}">{{.Status}}</span>
				{{if .Device}}<div class="dev">{{.Device}}</div>{{end}}
			</td>
			<td>
				{{if .Revoked}}
					<form class="inline" action="/restore" method="POST">
						<input type="hidden" name="key" value="{{.Key}}">
						<button class="restore" type="submit">Restore</button>
					</form>
				{{else}}
					<form class="inline" action="/revoke" method="POST">
						<input type="hidden" name="key" value="{{.Key}}">
						<button class="revoke" type="submit">Revoke</button>
					</form>
				{{end}}
			</td>
		</tr>
		{{end}}
	</table>
	<script>
		function filterTable() {
			var f = document.getElementById("search").value.toUpperCase();
			var tr = document.getElementById("keyTable").getElementsByTagName("tr");
			for (var i = 1; i < tr.length; i++) {
				tr[i].style.display = (tr[i].textContent || tr[i].innerText).toUpperCase().indexOf(f) > -1 ? "" : "none";
			}
		}
	</script>
</body>
</html>`

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
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return false
	}
	return true
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
	msg := "Name saved"
	if name == "" {
		msg = "Name cleared"
	}
	http.Redirect(w, r, "/?msg="+template.URLQueryEscaper(msg), http.StatusSeeOther)
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
	http.Redirect(w, r, "/?msg="+template.URLQueryEscaper("Key revoked - the bot will refuse to run"), http.StatusSeeOther)
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
	http.Redirect(w, r, "/?msg="+template.URLQueryEscaper("Key restored"), http.StatusSeeOther)
}

// ==========================================
// BOT API: activate + verify
// ==========================================
func writeJSON(w http.ResponseWriter, code int, v ActivationResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
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
